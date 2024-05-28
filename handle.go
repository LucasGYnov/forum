package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Clé de chiffrement pour les cookies de sessio
var store = sessions.NewCookieStore([]byte("keySession"))

// Configuration de la durée d'expiration du cookie (par exemple, 40 secondes)
const sessionExpiration = 1 * time.Hour

type RegisterHandler struct {
	db        *sql.DB
	dbInitErr error
}

type User struct {
	ID          int
	Username    string
	Email       string
	Image       []byte
	Base64Image string
}

type App struct {
	config *oauth2.Config
}

type Goauth struct {
	Id            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
}

var jsonResp Goauth

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/login/oauth" {
		if r.Method == "GET" {
			url := a.config.AuthCodeURL("state", oauth2.AccessTypeOffline)
			http.Redirect(w, r, url, http.StatusTemporaryRedirect)
		}
	}
	if r.URL.Path == "/callback" {
		if r.Method == "GET" {
			code := r.URL.Query().Get("code")

			t, err := a.config.Exchange(context.Background(), code)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			client := a.config.Client(context.Background(), t)
			resp, _ := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")

			if err = json.NewDecoder(resp.Body).Decode(&jsonResp); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			fmt.Printf("ID: %s\n", jsonResp.Id)
			fmt.Printf("Email: %s\n", jsonResp.Email)
			fmt.Printf("Verified Email: %t\n", jsonResp.VerifiedEmail)
			fmt.Printf("Picture: %s\n", jsonResp.Picture)
			u := new(User)
			u.processLoginGoogle(w, r, jsonResp)

		}
	}
}
func (u *User) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	session, err := store.Get(r, "userSession")
	if err != nil {
		log.Printf("Erreur lors de la récupération de la session: %v", err)
		http.Error(w, "Erreur de session", http.StatusInternalServerError)
		return
	}
	if r.URL.Path == "/" {
		if r.Method == "GET" {
			tmpl, err := template.ParseFiles("index.html")
			if err != nil {
				log.Printf("Erreur lors du parsing du template index.html: %v", err)
				http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
				return
			}
			tmpl.Execute(w, u)
			return
		}
		if r.Method == "POST" {

			err := r.ParseMultipartForm(20 << 20) // 20 MB max file size
			if err != nil {
				log.Printf("Erreur lors du parsing du formulaire: %v", err)
				http.Error(w, "Erreur lors du parsing du formulaire", http.StatusInternalServerError)
				return
			}

			message := r.Form.Get("editor-container") // Utilisez .Get() pour récupérer une seule valeur
			log.Printf("Message: %s", message)

			// Utilisez le message comme vous le souhaitez ici...

			http.Redirect(w, r, "http://localhost:5500/", http.StatusSeeOther)
			return
		}

	}
	if r.URL.Path == "/signin" {
		if r.Method == "GET" {
			tmpl, err := template.ParseFiles("signin.html")
			if err != nil {
				http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
				return
			}
			tmpl.Execute(w, nil)
			return
		} else if r.Method == "POST" {
			u.processRegistration(w, r)
			return
		}
	}
	if r.URL.Path == "/login" {
		if r.Method == "GET" {
			tmpl, err := template.ParseFiles("login.html")
			if err != nil {
				http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
				return
			}
			tmpl.Execute(w, u)
			return
		} else if r.Method == "POST" {
			u.processLogin(w, r)
			return
		}
	}

	if r.URL.Path == "/profile" {
		if r.Method == "GET" {
			if userID, ok := session.Values["userID"].(int); ok {
				u.loadUserFromDB(userID)
				u.handleUser(w, r)
				return
			}

		} else if r.Method == "POST" {
			fmt.Println("demande de deco")
			http.Redirect(w, r, "/logout", http.StatusSeeOther)
			return
		}
	}
	if r.URL.Path == "/logout" {
		if r.Method == "GET" {
			for key := range session.Values {
				delete(session.Values, key)
			}
			session.Options.MaxAge = -1

			// Sauvegarder la session pour appliquer les changements
			err = session.Save(r, w)
			if err != nil {
				http.Error(w, "Erreur lors de la sauvegarde de la session", http.StatusInternalServerError)
				return
			}
			u.processLogout(w, r)

			return
		}
		if r.Method == "POST" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return

		}
	}
	if r.URL.Path == "/posts" {
		if r.Method == "GET" {
			tmpl, err := template.ParseFiles("post.html")
			if err != nil {
				http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
				return
			}
			tmpl.Execute(w, u)
			return
		}
	}

	http.NotFound(w, r)
}

/* func (h *RegisterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.db, h.dbInitErr = sql.Open("sqlite3", "./forumv3.db")
	if h.dbInitErr != nil {
		http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
		return
	}

	if r.URL.Path == "/" {
		if r.Method == "GET" {
			tmpl, err := template.ParseFiles("register.html")
			if err != nil {
				http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
				return
			}
			tmpl.Execute(w, nil)
			return
		} else if r.Method == "POST" {
			h.processRegistration(w, r)
			return
		}
	}
	http.NotFound(w, r)
} */

func (u *User) processLoginGoogle(w http.ResponseWriter, r *http.Request, googleInfo Goauth) {
	db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
	if dbInitErr != nil {
		http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	err := db.QueryRow("SELECT user_id, username, email FROM users WHERE email=? AND auth_provider = 'google'", googleInfo.Email).Scan(&u.ID, &u.Username, &u.Email)

	if err != nil {
		if err == sql.ErrNoRows {
			/* http.Error(w, "Aucun utilisateur trouvé avec cet ID", http.StatusNotFound)
			return */

			u.processRegistrationGoogle(w, r, googleInfo.Email, googleInfo.Name, googleInfo.Picture)

		}
		log.Printf("Erreur lors de la récupération des informations de l'utilisateur: %v", err)
		http.Error(w, "Erreur lors de la récupération des informations de l'utilisateur", http.StatusInternalServerError)
		return
	}

	session, err := store.Get(r, "userSession")
	if err != nil {
		log.Printf("Erreur lors de la récupération de la session: %v", err)
		http.Error(w, "Erreur de session", http.StatusInternalServerError)
		return
	}

	session.Values["userID"] = u.ID
	fmt.Println("Logged in user ID:", session.Values["userID"])

	// Définir l'expiration de la session
	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   int(sessionExpiration.Seconds()), // Durée en secondes
		HttpOnly: true,                             // Pour des raisons de sécurité
	}

	err = session.Save(r, w)
	if err != nil {
		log.Printf("Erreur lors de la sauvegarde de la session: %v", err)
		http.Error(w, "Erreur lors de la sauvegarde de la session", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

func (u *User) processLogin(w http.ResponseWriter, r *http.Request) {
	db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
	if dbInitErr != nil {
		http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	r.ParseMultipartForm(20 << 20) // 20 MB max file size

	email := r.FormValue("email")
	password := r.FormValue("password")
	err := db.QueryRow("SELECT user_id, username, email FROM users WHERE email=? AND password=? AND auth_provider = 'website'", email, password).Scan(&u.ID, &u.Username, &u.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Aucun utilisateur trouvé avec cet ID", http.StatusNotFound)
			return
		}
		log.Printf("Erreur lors de la récupération des informations de l'utilisateur: %v", err)
		http.Error(w, "Erreur lors de la récupération des informations de l'utilisateur", http.StatusInternalServerError)
		return
	}

	// Sauvegarder l'ID de l'utilisateur dans la session
	session, err := store.Get(r, "userSession")
	if err != nil {
		log.Printf("Erreur lors de la récupération de la session: %v", err)
		http.Error(w, "Erreur de session", http.StatusInternalServerError)
		return
	}

	session.Values["userID"] = u.ID
	fmt.Println("Logged in user ID:", session.Values["userID"])

	// Définir l'expiration de la session
	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   int(sessionExpiration.Seconds()), // Durée en secondes
		HttpOnly: true,                             // Pour des raisons de sécurité
	}

	err = session.Save(r, w)
	if err != nil {
		log.Printf("Erreur lors de la sauvegarde de la session: %v", err)
		http.Error(w, "Erreur lors de la sauvegarde de la session", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

func downloadImage(url string) ([]byte, error) {
	// Effectuer une requête GET pour télécharger l'image
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Vérifier le statut de la réponse
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch image: %s", resp.Status)
	}

	// Lire le contenu de la réponse dans une variable []byte
	imageData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Retourner le contenu de l'image
	return imageData, nil
}
func (u *User) processRegistrationGoogle(w http.ResponseWriter, r *http.Request, email string, username string, picture string) {
	db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
	if dbInitErr != nil {
		http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
		return
	}

	// URL de l'image à télécharger
	profile_picture_URL := picture

	// Télécharger l'image et stocker temporairement
	tempFile, err := downloadImage(profile_picture_URL)
	if err != nil {
		fmt.Printf("Error downloading image: %v\n", err)
		return
	}
	fmt.Printf("Image downloaded and saved to: %s\n", tempFile)

	// Insérer l'utilisateur dans la base de données
	stmt, err := db.Prepare("INSERT INTO users(username, email, profile_picture, auth_provider) VALUES(?, ?, ?,?)")
	if err != nil {
		http.Error(w, "Erreur lors de la préparation de la requête", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(username, email, tempFile, "google")
	if err != nil {
		http.Error(w, "Erreur lors de l'exécution de la requête", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)

}
func (u *User) processRegistration(w http.ResponseWriter, r *http.Request) {
	db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
	if dbInitErr != nil {
		http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
		return
	}

	r.ParseMultipartForm(20 << 20) // 20 MB max file size

	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")

	file, _, err := r.FormFile("profile_picture")
	if err != nil {
		http.Error(w, "Erreur lors de l'obtention du fichier", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Lire le fichier dans un slice de bytes
	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, file); err != nil {
		http.Error(w, "Erreur lors de la lecture du fichier", http.StatusInternalServerError)
		return
	}
	fileBytes := buf.Bytes()

	// Insérer l'utilisateur dans la base de données
	stmt, err := db.Prepare("INSERT INTO users(username, email, password, profile_picture,auth_provider) VALUES(?, ?, ?, ?,?)")
	if err != nil {
		http.Error(w, "Erreur lors de la préparation de la requête", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(username, email, password, fileBytes, "website")
	if err != nil {
		http.Error(w, "Erreur lors de l'exécution de la requête", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (u *User) loadUserFromDB(userID int) {
	db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
	if dbInitErr != nil {
		log.Printf("Erreur de base de données: %v", dbInitErr)
		return
	}
	defer db.Close()

	err := db.QueryRow("SELECT username, email, profile_picture FROM users WHERE user_id=?", userID).Scan(&u.Username, &u.Email, &u.Image)
	if err != nil {
		log.Printf("Erreur lors de la récupération des informations de l'utilisateur: %v", err)
	}
}

func (u *User) handleUser(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("usertest.html")
	if err != nil {
		log.Printf("Erreur de serveur: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return
	}
	data := struct {
		Username    string
		Email       string
		Image       []byte
		Base64Image string
	}{
		Username:    u.Username,
		Email:       u.Email,
		Image:       u.Image,
		Base64Image: base64.StdEncoding.EncodeToString(u.Image),
	}
	tmpl.Execute(w, data)
}

func (u *User) processLogout(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("logouttest.html")
	if err != nil {
		log.Printf("Erreur de serveur: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return

	}
	tmpl.Execute(w, nil)

}
func main() {
	clientId := "205949073068-pgfqbsm6h9bahpgaq505o8k7a7iidhcr.apps.googleusercontent.com"
	clientSecret := "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"

	conf := &oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		RedirectURL:  "http://localhost:5500/callback",
		Scopes:       []string{"email", "profile"},
		Endpoint:     google.Endpoint,
	}

	app := App{config: conf}

	fs := http.FileServer(http.Dir("public"))
	http.Handle("/public/", http.StripPrefix("/public/", fs))

	http.Handle("/", new(User))
	http.Handle("/signin", new(User))
	http.Handle("/profile", new(User))
	http.Handle("/login", new(User))
	http.Handle("/login/oauth", &app)
	http.Handle("/callback", &app)
	http.Handle("/logout", new(User))
	http.Handle("/posts", new(User))

	log.Fatal(http.ListenAndServe(":5500", nil))
}
