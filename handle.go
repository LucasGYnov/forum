package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
)

// Clé de chiffrement pour les cookies de session
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
				http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
				return
			}
			tmpl.Execute(w, u)
			return
		}
	}
	if r.URL.Path == "/register" {
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

func (u *User) processLogin(w http.ResponseWriter, r *http.Request) {
	db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
	if dbInitErr != nil {
		http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	r.ParseMultipartForm(10 << 20) // 10 MB max file size

	email := r.FormValue("emaild")
	password := r.FormValue("passwordd")
	err := db.QueryRow("SELECT user_id, username, email FROM users WHERE email=? AND password=?", email, password).Scan(&u.ID, &u.Username, &u.Email)
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

func (u *User) processRegistration(w http.ResponseWriter, r *http.Request) {
	db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
	if dbInitErr != nil {
		http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
		return
	}

	r.ParseMultipartForm(10 << 20) // 10 MB max file size

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
	stmt, err := db.Prepare("INSERT INTO users(username, email, password, profile_picture) VALUES(?, ?, ?, ?)")
	if err != nil {
		http.Error(w, "Erreur lors de la préparation de la requête", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(username, email, password, fileBytes)
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
	fs := http.FileServer(http.Dir("public"))
	http.Handle("/public/", http.StripPrefix("/public/", fs))

	http.Handle("/", new(User))
	http.Handle("/register", new(User))
	http.Handle("/profile", new(User))
	http.Handle("/login", new(User))
	http.Handle("/logout", new(User))

	log.Fatal(http.ListenAndServe(":5500", nil))
}
