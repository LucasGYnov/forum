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
	"net/url"
	"path"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
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
	Role        string
}

type Post struct {
	ID           int
	Title        string
	Description  string
	Image        []byte
	Base64Image  string
	Comments     []Comment
	CategoryName string
	Liked        bool
	Disliked     bool
	Nblike       int
	Nbdislike    int
}

type Category struct {
	ID          int
	Title       string
	NbPost      int
	Image       []byte
	Base64Image string
	Posts       []Post
	Description string
}

type Comment struct {
	ID         int
	AuthorId   int
	AuthorName string

	Description string
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

type Report struct {
	PostID  int
	Reason  string
	Comment string
	Status  string
}

var (
	reports     []Report
	reportsLock sync.Mutex
)

var jsonResp Goauth

var filterOrder string
var filterType string
var filterSubject string
var filterOther string

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

			var categories []Category

			db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
			if dbInitErr != nil {
				http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
				return
			}
			defer db.Close()

			request, err := db.Query("SELECT category_name FROM categories")
			if err != nil {
				log.Printf("Erreur de serveur: %v", err)
				http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
				return
			}
			defer request.Close()

			for request.Next() {
				var category Category
				if err := request.Scan(&category.Title); err != nil {
					log.Printf("Erreur de serveur: %v", err)
					http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
					return
				}
				categories = append(categories, category)
			}

			data := struct {
				Categories []Category
				User       *User
			}{

				Categories: categories,
				User:       u,
			}

			tmpl.Execute(w, data)
			return
		}
		if r.Method == "POST" {
			session, err := store.Get(r, "userSession")
			if err != nil {
				log.Printf("Erreur lors de la récupération de la session: %v", err)
				http.Error(w, "Erreur de session", http.StatusInternalServerError)
				return
			}

			_, ok := session.Values["userID"].(int)
			if !ok {
				http.Error(w, "You are not connected", http.StatusInternalServerError)
				return
			}
			db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")

			if dbInitErr != nil {
				http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
				return
			}

			err = r.ParseMultipartForm(20 << 20) // 20 MB max file size
			if err != nil {
				log.Printf("Erreur lors du parsing du formulaire: %v", err)
				http.Error(w, "Erreur lors du parsing du formulaire", http.StatusInternalServerError)
				return
			}
			r.ParseMultipartForm(20 << 20) // 20 MB max file size

			message := r.FormValue("post-message")

			title := r.FormValue("post-title")

			category := r.FormValue("post-subject")

			var categoryID int

			_ = db.QueryRow("SELECT category_id FROM categories WHERE category_name=?", category).Scan(&categoryID)

			file, _, err := r.FormFile("post-attachment")
			if err != nil {
				http.Error(w, "Erreur lors de l'obtention du fichier", http.StatusBadRequest)
				return
			}

			buf := bytes.NewBuffer(nil)
			if _, err := io.Copy(buf, file); err != nil {
				http.Error(w, "Erreur lors de la lecture du fichier", http.StatusInternalServerError)
				return
			}
			fileBytes := buf.Bytes()

			// Insérer l'utilisateur dans la base de données
			stmt, err := db.Prepare("INSERT INTO posts(posts_title, posts_description, posts_profile_picture, category_id, category_name) VALUES(?, ?, ?, ?, ?)")
			if err != nil {
				http.Error(w, "Erreur lors de la préparation de la requête", http.StatusInternalServerError)
				return
			}
			defer stmt.Close()
			imageString := base64.StdEncoding.EncodeToString(fileBytes)

			_, err = stmt.Exec(title, message, imageString, categoryID, category)
			if err != nil {
				http.Error(w, "Erreur lors de l'exécution de la requête", http.StatusInternalServerError)
				return
			}

			// Utilisez le message comme vous le souhaitez ici...

			http.Redirect(w, r, "http://localhost:5500/", http.StatusSeeOther)
			return
		}

	}
	if path.Base(r.URL.Path) == "post" {
		if r.Method == "GET" {
			u.postHandler(w, r)
		} else if r.Method == "POST" {
			u.createComment(w, r)
		}

	}

	if path.Base(r.URL.Path) == "category" {
		if r.Method == "GET" {
			categoryHandler(w, r)
		}
	}
	if r.URL.Path == "/like" {
		if r.Method == "POST" {
			fmt.Print("id user")
			fmt.Print(u.ID)
			dataType := r.FormValue("type")
			if dataType == "post" {
				postID := r.FormValue("post_id")
				postStatus := r.FormValue("isLiked")
				fmt.Println("post numero: " + postID)
				fmt.Println("post status :" + postStatus)

				db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
				if dbInitErr != nil {
					http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
					return
				}

				if postStatus == "false" {

					_, err = db.Exec("INSERT INTO postslikes (user_id, post_id) VALUES (?, ?)", u.ID, postID)
					if err != nil {
						log.Printf("Erreur de serveur: %v", err)
						http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
						return
					}
				} else {
					_, err = db.Exec("DELETE FROM postslikes WHERE user_id = ? AND post_id = ?", u.ID, postID)
					if err != nil {
						log.Printf("Erreur de serveur: %v", err)
						http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
						return
					}
				}

			} else if dataType == "category" {
				categoryID := r.FormValue("category_id")
				categoryStatus := r.FormValue("isLiked")
				fmt.Println("post numero: " + categoryID)
				fmt.Println("post status :" + categoryStatus)

				db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
				if dbInitErr != nil {
					http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
					return
				}

				if categoryStatus == "false" {

					_, err = db.Exec("INSERT INTO categorieslikes (user_id, category_id) VALUES (?, ?)", u.ID, categoryID)
					if err != nil {
						log.Printf("Erreur de serveur: %v", err)
						http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
						return
					}

				} else {
					_, err = db.Exec("DELETE FROM categorieslikes WHERE user_id = ? AND category_id = ?", u.ID, categoryID)
					if err != nil {
						log.Printf("Erreur de serveur: %v", err)
						http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
						return
					}

				}

			}

		}
	}
	if r.URL.Path == "/apply-filters" {
		if r.Method == "POST" {
			filterOrder = r.FormValue("filter-order")
			filterType = r.FormValue("filter-type")
			filterSubject = r.FormValue("filter-subject")
			filterOther = r.FormValue("filter-other")

			http.Redirect(w, r, "/posts", http.StatusSeeOther)

		}
	}
	if r.URL.Path == "/apply-filters-category" {
		if r.Method == "POST" {
			filterOrder = r.FormValue("filter-order")
			filterType = r.FormValue("filter-type")
			filterSubject = r.FormValue("filter-subject")
			filterOther = r.FormValue("filter-other")

			http.Redirect(w, r, "/categories", http.StatusSeeOther)

		}
	}

	if r.URL.Path == "/submit-evaluation" {
		if r.Method == "POST" {
			session, err := store.Get(r, "userSession")
			if err != nil {
				log.Printf("Erreur lors de la récupération de la session: %v", err)
				http.Error(w, "Erreur de session", http.StatusInternalServerError)
				return
			}

			userID, ok := session.Values["userID"].(int)
			if ok && userID > 0 {

				evaluationDislike := r.FormValue("evaluationDislike")
				evaluationLike := r.FormValue("evaluationLike")

				postID := r.FormValue("post_id")

				if evaluationDislike == "" {

					db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
					if dbInitErr != nil {
						http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
						return
					}

					defer db.Close()

					var exists bool
					query := "SELECT EXISTS(SELECT 1 FROM postsdislikes WHERE post_id = ? AND user_id = ?)"
					err = db.QueryRow(query, postID, userID).Scan(&exists)
					if err != nil {
						panic(err)
					}

					if exists {

						fmt.Println("enleve le dislike")
						_, err = db.Exec("DELETE FROM postsdislikes WHERE user_id = ? AND post_id = ?", userID, postID)
						if err != nil {
							log.Printf("Erreur de serveur: %v", err)
							http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
							return
						}

						_, err = db.Exec("UPDATE posts SET posts_nbdislike = posts_nbdislike - 1 WHERE posts_id = ?", postID)
						if err != nil {
							log.Printf("Erreur de serveur: %v", err)
							http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
							return
						}

					}

				}
				if evaluationLike == "" {

					db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")

					if dbInitErr != nil {
						http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
						return
					}
					defer db.Close()

					var exists bool
					query := "SELECT EXISTS(SELECT 1 FROM postslikes WHERE post_id = ? AND user_id = ?)"
					err = db.QueryRow(query, postID, userID).Scan(&exists)
					if err != nil {
						panic(err)
					}

					if exists {
						fmt.Println("enleve like")

						_, err = db.Exec("DELETE FROM postslikes WHERE user_id = ? AND post_id = ?", userID, postID)
						if err != nil {
							log.Printf("Erreur de serveur: %v", err)
							http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
							return
						}
						_, err = db.Exec("UPDATE posts SET posts_nblike = posts_nblike - 1 WHERE posts_id = ?", postID)
						if err != nil {
							log.Printf("Erreur de serveur: %v", err)
							http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
							return
						}

					}

				}

				if evaluationLike == "like" {
					fmt.Println("a liké")

					db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
					if dbInitErr != nil {
						http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
						return
					}
					defer db.Close()

					_, err = db.Exec("INSERT INTO postslikes (user_id, post_id) VALUES (?, ?)", userID, postID)
					if err != nil {
						log.Printf("Erreur de serveur: %v", err)
						http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
						return
					}
					_, err = db.Exec("UPDATE posts SET posts_nblike = posts_nblike + 1 WHERE posts_id = ?", postID)
					if err != nil {
						log.Printf("Erreur de serveur: %v", err)
						http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
						return
					}

					//Check if it was disliked
					var exists bool
					query := "SELECT EXISTS(SELECT 1 FROM postsdislikes WHERE post_id = ? AND user_id = ?)"
					err = db.QueryRow(query, postID, userID).Scan(&exists)
					if err != nil {
						panic(err)
					}

					if exists {
						_, err = db.Exec("DELETE FROM postsdislikes WHERE user_id = ? AND post_id = ?", userID, postID)
						if err != nil {
							log.Printf("Erreur de serveur: %v", err)
							http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
							return
						}

						_, err = db.Exec("UPDATE posts SET posts_nbdislike = posts_nbdislike - 1 WHERE posts_id = ?", postID)
						if err != nil {
							log.Printf("Erreur de serveur: %v", err)
							http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
							return
						}

					}

				} else if evaluationDislike == "dislike" {
					fmt.Println("a disliké")

					db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
					if dbInitErr != nil {
						http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
						return
					}
					defer db.Close()

					_, err = db.Exec("INSERT INTO postsdislikes (user_id, post_id) VALUES (?, ?)", userID, postID)
					if err != nil {
						log.Printf("Erreur de serveur: %v", err)
						http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
						return
					}
					_, err = db.Exec("UPDATE posts SET posts_nbdislike = posts_nbdislike + 1 WHERE posts_id = ?", postID)
					if err != nil {
						log.Printf("Erreur de serveur: %v", err)
						http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
						return
					}

					//Check if it was liked
					var exists bool
					query := "SELECT EXISTS(SELECT 1 FROM postslikes WHERE post_id = ? AND user_id = ?)"
					err = db.QueryRow(query, postID, userID).Scan(&exists)
					if err != nil {
						panic(err)
					}

					if exists {
						_, err = db.Exec("DELETE FROM postslikes WHERE user_id = ? AND post_id = ?", userID, postID)
						if err != nil {
							log.Printf("Erreur de serveur: %v", err)
							http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
							return
						}
						_, err = db.Exec("UPDATE posts SET posts_nblike = posts_nblike - 1 WHERE posts_id = ?", postID)
						if err != nil {
							log.Printf("Erreur de serveur: %v", err)
							http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
							return
						}
					}

				}
			} else {
				http.Error(w, "You are not connected", http.StatusInternalServerError)

			}
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
			//Verify if already connected
			session, err := store.Get(r, "userSession")
			if err != nil {
				log.Printf("Erreur lors de la récupération de la session: %v", err)
				http.Error(w, "Erreur de session", http.StatusInternalServerError)
				return
			}

			_, ok := session.Values["userID"].(int)
			if !ok {

				tmpl, err := template.ParseFiles("login.html")
				if err != nil {
					http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
					return
				}
				tmpl.Execute(w, u)
				return
			} else {
				http.Redirect(w, r, "/profile", http.StatusSeeOther)

			}

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
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)

			}

		} else if r.Method == "POST" {
			fmt.Println("demande de deco")
			http.Redirect(w, r, "/logout", http.StatusSeeOther)
			return
		}
	}

	if r.URL.Path == "/submit-email" {
		if r.Method == "POST" {

			newEmail := r.FormValue("newEmail")

			u.Email = newEmail

			session, err := store.Get(r, "userSession")
			if err != nil {
				log.Printf("Erreur lors de la récupération de la session: %v", err)
				http.Error(w, "Erreur de session", http.StatusInternalServerError)
				return
			}

			session.Values["userEmail"] = newEmail

			err = session.Save(r, w)
			if err != nil {
				log.Printf("Erreur lors de la sauvegarde de la session: %v", err)
				http.Error(w, "Erreur lors de la sauvegarde de la session", http.StatusInternalServerError)
				return
			}

			db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
			if dbInitErr != nil {
				http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
				return
			}
			stmt, err := db.Prepare("UPDATE users SET email = ? WHERE user_id = ?")

			if err != nil {
				http.Error(w, "Erreur lors de la préparation de la requête", http.StatusInternalServerError)
				return
			}
			defer stmt.Close()

			userID, ok := session.Values["userID"].(int)
			if !ok {
				http.Error(w, "You are not connected", http.StatusInternalServerError)
				return
			}
			_, err = stmt.Exec(newEmail, userID)
			if err != nil {
				http.Error(w, "Erreur lors de l'exécution de la requête", http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, "/profile", http.StatusSeeOther)
		}
	}

	if r.URL.Path == "/submit-password" {
		if r.Method == "POST" {
			r.ParseMultipartForm(20 << 20) // 20 MB max file size
			newPassword := r.FormValue("newPassword")
			oldPassword := r.FormValue("oldPassword")

			session, err := store.Get(r, "userSession")
			if err != nil {
				log.Printf("Erreur lors de la récupération de la session: %v", err)
				http.Error(w, "Erreur de session", http.StatusInternalServerError)
				return
			}

			db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
			if dbInitErr != nil {
				http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
				return
			}
			stmt, err := db.Prepare("UPDATE users SET password = ? WHERE user_id = ?")

			if err != nil {
				http.Error(w, "Erreur lors de la préparation de la requête", http.StatusInternalServerError)
				return
			}
			defer stmt.Close()

			userID, ok := session.Values["userID"].(int)
			if !ok {
				http.Error(w, "You are not connected", http.StatusInternalServerError)
				return

			}

			userEmail, ok := session.Values["userEmail"].(string)
			if !ok {
				http.Error(w, "You are not connected", http.StatusInternalServerError)
				return
			}

			var verifPassword string

			_ = db.QueryRow("SELECT password FROM users WHERE email=? AND password=? ", userEmail, oldPassword).Scan(&verifPassword)

			if oldPassword != verifPassword {

				http.Error(w, "Mauvais mot de passe", http.StatusNotFound)
				return

			}

			_, err = stmt.Exec(newPassword, userID)
			if err != nil {
				http.Error(w, "Erreur lors de l'exécution de la requête", http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, "/profile", http.StatusSeeOther)
		}
	}
	if r.URL.Path == "/submit-picture" {
		if r.Method == "POST" {

			r.ParseMultipartForm(20 << 20)

			file, _, err := r.FormFile("newImage")
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
			newPicture := buf.Bytes()

			session, err := store.Get(r, "userSession")
			if err != nil {
				log.Printf("Erreur lors de la récupération de la session: %v", err)
				http.Error(w, "Erreur de session", http.StatusInternalServerError)
				return
			}

			err = session.Save(r, w)
			if err != nil {
				log.Printf("Erreur lors de la sauvegarde de la session: %v", err)
				http.Error(w, "Erreur lors de la sauvegarde de la session", http.StatusInternalServerError)
				return
			}

			db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
			if dbInitErr != nil {
				http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
				return
			}
			stmt, err := db.Prepare("UPDATE users SET profile_picture = ? WHERE user_id = ?")

			if err != nil {
				http.Error(w, "Erreur lors de la préparation de la requête", http.StatusInternalServerError)
				return
			}
			defer stmt.Close()

			userID, ok := session.Values["userID"].(int)
			if !ok {
				http.Error(w, "You are not connected", http.StatusInternalServerError)
				return
			}
			_, err = stmt.Exec(newPicture, userID)
			if err != nil {
				http.Error(w, "Erreur lors de l'exécution de la requête", http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, "/profile", http.StatusSeeOther)

		}
	}
	if r.URL.Path == "/submit-username" {
		if r.Method == "POST" {
			newUsername := r.FormValue("newUsername")
			fmt.Println(newUsername)

			session, err := store.Get(r, "userSession")
			if err != nil {
				log.Printf("Erreur lors de la récupération de la session: %v", err)
				http.Error(w, "Erreur de session", http.StatusInternalServerError)
				return
			}

			session.Values["userName"] = newUsername

			err = session.Save(r, w)
			if err != nil {
				log.Printf("Erreur lors de la sauvegarde de la session: %v", err)
				http.Error(w, "Erreur lors de la sauvegarde de la session", http.StatusInternalServerError)
				return
			}

			db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
			if dbInitErr != nil {
				http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
				return
			}
			stmt, err := db.Prepare("UPDATE users SET username = ? WHERE user_id = ?")

			if err != nil {
				http.Error(w, "Erreur lors de la préparation de la requête", http.StatusInternalServerError)
				return
			}
			defer stmt.Close()

			userID, ok := session.Values["userID"].(int)
			if !ok {
				http.Error(w, "You are not connected", http.StatusInternalServerError)
				return
			}
			_, err = stmt.Exec(newUsername, userID)
			if err != nil {
				http.Error(w, "Erreur lors de l'exécution de la requête", http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, "/profile", http.StatusSeeOther)

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
			u.Feed(w, r)
			return
		}
	}
	if r.URL.Path == "/categories" {
		if r.Method == "GET" {
			u.Feed2(w, r)
			return
		}
	}

	if r.URL.Path == "/category" {
		if r.Method == "POST" {
			u.createCategory(w, r)
			return
		}
	}

	if r.URL.Path == "/user-profile" {
		if r.Method == "GET" {
			tmpl, err := template.ParseFiles("user-profile.html")
			if err != nil {
				http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
				return
			}
			tmpl.Execute(w, u)
			return
		}
	}

}

/*
	 func (h *RegisterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	}
*/

func (u *User) postHandler(w http.ResponseWriter, r *http.Request) {
	// Récupérer l'ID du post depuis la requête
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Charger les détails du post depuis la base de données
	var post Post
	db, err := sql.Open("sqlite3", "./forumv3.db")
	if err != nil {
		http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
		return
	}
	defer db.Close()
	err = db.QueryRow("SELECT posts_title, posts_description, posts_profile_picture, category_name, posts_nblike, posts_nbdislike FROM posts WHERE posts_id=?", id).Scan(&post.Title, &post.Description, &post.Base64Image, &post.CategoryName, &post.Nblike, &post.Nbdislike)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Aucun post trouvé avec cet ID", http.StatusNotFound)
			return
		}
		log.Printf("Erreur lors de la récupération des informations du post: %v", err)
		http.Error(w, "Erreur lors de la récupération des informations du post", http.StatusInternalServerError)
		return
	}
	post.ID = id
	post.Comments = getComments(w, r, id)

	session, err := store.Get(r, "userSession")
	if err != nil {
		log.Printf("Erreur lors de la récupération de la session: %v", err)
		http.Error(w, "Erreur de session", http.StatusInternalServerError)
		return
	}

	userID, ok := session.Values["userID"].(int)
	if !ok {
		post.Liked = false
		post.Disliked = false
	} else {
		var exists bool

		// Query to check if a row with id = 1 exists
		query := "SELECT EXISTS(SELECT 1 FROM postslikes WHERE post_id = ? AND user_id = ?)"
		err = db.QueryRow(query, post.ID, userID).Scan(&exists)
		if err != nil {
			panic(err)
		}

		if exists {
			post.Liked = true
		} else {
			post.Liked = false
		}

		query = "SELECT EXISTS(SELECT 1 FROM postsdislikes WHERE post_id = ? AND user_id = ?)"
		err = db.QueryRow(query, post.ID, userID).Scan(&exists)
		if err != nil {
			panic(err)
		}

		if exists {
			post.Disliked = true
		} else {
			post.Disliked = false
		}

	}

	// Préparer les données à envoyer au template
	tmpl, err := template.ParseFiles("uniquePost.html")
	if err != nil {
		log.Printf("Erreur lors de l'analyse du template: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return
	}

	var idUSER int
	idUSER, err = getUserIdFromRequest(r)
	if err != nil {

		data := struct {
			Post    Post
			IsAdmin bool
		}{
			Post:    post,
			IsAdmin: false,
		}

		// Exécuter le template avec les données
		tmpl.Execute(w, data)
		return
	} else {
		// Load the current user from the database
		u.loadUserFromDB(idUSER)

		data := struct {
			Post    Post
			IsAdmin bool
		}{
			Post:    post,
			IsAdmin: u.Role == "admin" || u.Role == "moderator",
		}

		// Exécuter le template avec les données
		tmpl.Execute(w, data)

	}

}
func categoryHandler(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	fmt.Println(id)

	var category Category

	db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
	if dbInitErr != nil {
		http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	err = db.QueryRow("SELECT category_name, category_description, category_profile_picture FROM categories WHERE category_id=?", id).Scan(&category.Title, &category.Description, &category.Base64Image)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Aucun utilisateur trouvé avec cet ID", http.StatusNotFound)
			return
		}
		log.Printf("Erreur lors de la récupération des informations de l'utilisateur: %v", err)
		http.Error(w, "Erreur lors de la récupération des informations de l'utilisateur", http.StatusInternalServerError)
		return
	}
	category.Posts = getPosts(w, r, id)
	tmpl, err := template.ParseFiles("uniqueCategory.html")
	if err != nil {
		log.Printf("%v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, category)

}

func (u *User) createComment(w http.ResponseWriter, r *http.Request) {

	session, err := store.Get(r, "userSession")
	if err != nil {
		log.Printf("Erreur lors de la récupération de la session: %v", err)
		http.Error(w, "Erreur de session", http.StatusInternalServerError)
		return
	}

	userID, ok := session.Values["userID"].(int)
	if !ok {
		http.Error(w, "You are not connected", http.StatusInternalServerError)
		return
	}

	userEmail, ok := session.Values["userEmail"].(string)
	if !ok {
		http.Error(w, "You are not connected", http.StatusInternalServerError)
		return
	}

	userProfilePicture, ok := session.Values["userProfile_Picture"].(string)
	if !ok {
		http.Error(w, "You are not connected", http.StatusInternalServerError)
		return
	}

	userName, ok := session.Values["userName"].(string)
	if !ok {
		http.Error(w, "You are not connected", http.StatusInternalServerError)
		return
	}
	u.ID = userID
	u.Email = userEmail
	u.Base64Image = userProfilePicture
	u.Username = userName

	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	post_id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
	if dbInitErr != nil {
		http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
		return
	}

	err = r.ParseMultipartForm(20 << 20) // 20 MB max file size
	if err != nil {
		log.Printf("Erreur lors du parsing du formulaire: %v", err)
		http.Error(w, "Erreur lors du parsing du formulaire", http.StatusInternalServerError)
		return
	}
	r.ParseMultipartForm(20 << 20) // 20 MB max file size

	message := r.FormValue("response-message")

	file, _, err := r.FormFile("response-attachment")

	if err == nil {
		buf := bytes.NewBuffer(nil)
		if _, err := io.Copy(buf, file); err != nil {
			http.Error(w, "Erreur lors de la lecture du fichier", http.StatusInternalServerError)
			return
		}
		fileBytes := buf.Bytes()
		imageString := base64.StdEncoding.EncodeToString(fileBytes)
		imageString = "image"
		fmt.Println(imageString)

	}

	// Insérer l'utilisateur dans la base de données
	stmt, err := db.Prepare("INSERT INTO comments2(comments2_text, comments2_post_id, comments2_author_id) VALUES(?, ?, ?)")
	if err != nil {
		http.Error(w, "Erreur lors de la préparation de la requête", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(message, post_id, u.ID)
	if err != nil {
		http.Error(w, "Erreur lors de l'exécution de la requête", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("UPDATE posts SET posts_nbcomment = posts_nbcomment + 1 WHERE posts_id = ?", post_id)
	if err != nil {
		log.Printf("Erreur de serveur: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return
	}
	// Utilisez le message comme vous le souhaitez ici...
	url := fmt.Sprintf("http://localhost:5500/post?id=%v ", post_id)

	http.Redirect(w, r, url, http.StatusSeeOther)

}

func (u *User) processLoginGoogle(w http.ResponseWriter, r *http.Request, googleInfo Goauth) {
	db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
	if dbInitErr != nil {
		http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	err := db.QueryRow("SELECT user_id, username, email, profile_picture FROM users WHERE email=? AND auth_provider = 'google'", googleInfo.Email).Scan(&u.ID, &u.Username, &u.Email, &u.Base64Image)

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
	session.Values["userEmail"] = u.Email
	session.Values["userProfile_Picture"] = u.Base64Image
	session.Values["userName"] = u.Username
	session.Values["role"] = u.Role

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
	cookie := &http.Cookie{
		Name:     "user_id",
		Value:    strconv.Itoa(u.ID),
		Path:     "/",
		MaxAge:   int(sessionExpiration.Seconds()), //same expiration as the session
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)

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
	motDePasse := []byte(password)

	var mdpHache string
	db.QueryRow("SELECT password FROM users WHERE email=? AND auth_provider = 'website'", email).Scan(&mdpHache)

	// Convertir le mot de passe en clair en bytes

	// Comparer le mot de passe en clair avec le mot de passe haché
	err := bcrypt.CompareHashAndPassword([]byte(mdpHache), motDePasse)
	if err != nil {
		// Si les mots de passe ne correspondent pas
		http.Error(w, "Mot de passe incorrect", http.StatusUnauthorized)
		return
	}

	err = db.QueryRow("SELECT user_id, username, email FROM users WHERE email=? AND password=? AND auth_provider = 'website'", email, mdpHache).Scan(&u.ID, &u.Username, &u.Email)
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
	session.Values["userEmail"] = u.Email
	session.Values["userProfile_Picture"] = u.Base64Image
	session.Values["userName"] = u.Username
	session.Values["role"] = u.Role

	// Définir l'expiration de la session
	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   int(sessionExpiration.Seconds()), // Durée en secondes
		HttpOnly: true,                             // Pour des raisons de sécurité
	}

	//Set a cookie with the user's ID
	cookie := &http.Cookie{
		Name:     "user_id",
		Value:    strconv.Itoa(u.ID),
		Path:     "/",
		MaxAge:   int(sessionExpiration.Seconds()), //same expiration as the session
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)

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
	// Mot de passe en clair
	motDePasse := []byte(password)

	// Génération d'un sel et hachage du mot de passe avec le sel
	motDePasseHache, err := bcrypt.GenerateFromPassword(motDePasse, bcrypt.DefaultCost)
	if err != nil {
		fmt.Println(err)
		return
	}
	password = string(motDePasseHache)

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

func (u *User) loadUserFromDB(userID int) error {
	db, err := sql.Open("sqlite3", "./forumv3.db")
	if err != nil {
		return err
	}
	defer db.Close()

	err = db.QueryRow("SELECT username, role FROM users WHERE user_id=?", userID).Scan(&u.Username, &u.Role)
	if err != nil {
		return err
	}

	u.ID = userID
	return nil
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
		Role        string
	}{
		Username:    u.Username,
		Email:       u.Email,
		Image:       u.Image,
		Base64Image: base64.StdEncoding.EncodeToString(u.Image),
		Role:        u.Role,
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
func getComments(w http.ResponseWriter, r *http.Request, postID int) []Comment {

	var comments []Comment

	/* 	posts = append(posts, Post{Title: "Post 1", Description: "This is the first post"})
	   	posts = append(posts, Post{Title: "Post 2", Description: "This is the second post"})
	*/
	db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
	if dbInitErr != nil {
		http.Error(w, "Erreur de base de données", http.StatusInternalServerError)

	}
	defer db.Close()
	fmt.Println(postID)

	contents, err := db.Query("SELECT comments2_text, comments2_author_id FROM comments2 WHERE comments2_post_id = ?", postID)
	if err != nil {
		log.Printf("Erreur de serveur: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return nil

	}
	/* 	defer contents.Close()
	 */
	for contents.Next() {
		var comment Comment
		err := contents.Scan(&comment.Description, &comment.AuthorId)
		if err != nil {
			log.Printf("Erreur de serveurs: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return nil

		}
		authorErr := db.QueryRow("SELECT username FROM users WHERE user_id=?", comment.AuthorId).Scan(&comment.AuthorName)
		if authorErr != nil {
			log.Printf("Erreur de serveurss: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return nil

		}

		comments = append(comments, comment)
		fmt.Println(comments)

	}

	if err := contents.Err(); err != nil {
		log.Printf("Erreur de serveursss: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return nil

	}

	return comments
}
func getPosts(w http.ResponseWriter, r *http.Request, categoryID int) []Post {

	var posts []Post

	/* 	posts = append(posts, Post{Title: "Post 1", Description: "This is the first post"})
	   	posts = append(posts, Post{Title: "Post 2", Description: "This is the second post"})
	*/
	db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
	if dbInitErr != nil {
		http.Error(w, "Erreur de base de données", http.StatusInternalServerError)

	}
	defer db.Close()
	fmt.Println(categoryID)

	contents, err := db.Query("SELECT posts_description, posts_title, posts_profile_picture, posts_id, category_name FROM posts WHERE category_id = ?", categoryID)
	if err != nil {
		log.Printf("Erreur de serveur: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return nil

	}

	defer contents.Close()

	for contents.Next() {
		var post Post
		err := contents.Scan(&post.Description, &post.Title, &post.Base64Image, &post.ID, &post.CategoryName)
		if err != nil {
			log.Printf("Erreur de serveurs: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return nil

		}

		posts = append(posts, post)

	}

	if err := contents.Err(); err != nil {
		log.Printf("Erreur de serveursss: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return nil

	}

	return posts
}

func (u *User) Feed(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "userSession")
	if err != nil {
		log.Printf("Erreur lors de la récupération de la session: %v", err)
		http.Error(w, "Erreur de session", http.StatusInternalServerError)
		return
	}

	userID, ok := session.Values["userID"].(int)

	var posts []Post
	var categories []Category

	/* 	posts = append(posts, Post{Title: "Post 1", Description: "This is the first post"})
	   	posts = append(posts, Post{Title: "Post 2", Description: "This is the second post"})
	*/
	db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
	if dbInitErr != nil {
		http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	var contents *sql.Rows

	if filterOrder == "recent" {
		request, err := db.Query("SELECT posts_id, posts_profile_picture,  posts_title, posts_description, category_name, posts_nblike, posts_nbdislike FROM posts")
		if err != nil {
			log.Printf("Erreur de serveur: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return
		} else {
			contents = request
		}

	} else if filterOrder == "oldest" {
		request, err := db.Query("SELECT posts_id, posts_profile_picture, posts_title, posts_description, category_name, posts_nblike, posts_nbdislike FROM posts ORDER BY posts_id DESC")
		if err != nil {
			log.Printf("Erreur de serveur: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return
		} else {
			contents = request
		}

	} else if filterOrder == "most-likes" {
		request, err := db.Query("SELECT posts_id, posts_profile_picture, posts_title, posts_description, category_name, posts_nblike, posts_nbdislike FROM posts ORDER BY posts_nblike DESC")
		if err != nil {
			log.Printf("Erreur de serveur: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return
		}
		contents = request
	} else if filterOrder == "least-likes" {
		request, err := db.Query("SELECT posts_id, posts_profile_picture, posts_title, posts_description, category_name, posts_nblike, posts_nbdislike FROM posts ORDER BY  posts_nblike ASC")
		if err != nil {
			log.Printf("Erreur de serveur: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return
		}
		contents = request
	} else if filterOrder == "most-interactions" {
		request, err := db.Query("SELECT posts_id, posts_profile_picture, posts_title, posts_description, category_name, posts_nblike, posts_nbdislike FROM posts ORDER BY  posts_nbcomment DESC")
		if err != nil {
			log.Printf("Erreur de serveur: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return
		}
		contents = request
	} else if filterOrder == "least-interactions" {
		request, err := db.Query("SELECT posts_id, posts_profile_picture, posts_title, posts_description, category_name, posts_nblike, posts_nbdislike FROM posts ORDER BY  posts_nbcomment ASC")
		if err != nil {
			log.Printf("Erreur de serveur: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return
		}
		contents = request
	} else if filterOrder == "you liked" {
		request, err := db.Query("SELECT posts_id,posts_profile_picture, posts_title, posts_description, category_name, posts_nblike, posts_nbdislike FROM posts JOIN postslikes ON posts.posts_id = postslikes.post_id WHERE postslikes.user_id = ?", userID)
		if err != nil {
			log.Printf("Erreur de serveur: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return
		} else {
			contents = request
		}
	} else {
		request, err := db.Query("SELECT posts_id, posts_profile_picture,  posts_title, posts_description, category_name, posts_nblike, posts_nbdislike FROM posts")
		if err != nil {
			log.Printf("Erreur de serveur: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return
		} else {
			contents = request
		}
	}

	defer contents.Close()

	for contents.Next() {
		var post Post
		if err := contents.Scan(&post.ID, &post.Base64Image, &post.Title, &post.Description, &post.CategoryName, &post.Nblike, &post.Nbdislike); err != nil {
			log.Printf("Erreur de serveur: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return
		}
		if ok {
			var exists bool

			// Query to check if a row with id = 1 exists
			query := "SELECT EXISTS(SELECT 1 FROM postslikes WHERE post_id = ? AND user_id = ?)"
			err = db.QueryRow(query, post.ID, userID).Scan(&exists)
			if err != nil {
				panic(err)
			}

			if exists {
				post.Liked = true
			} else {
				post.Liked = false
			}

			query = "SELECT EXISTS(SELECT 1 FROM postsdislikes WHERE post_id = ? AND user_id = ?)"
			err = db.QueryRow(query, post.ID, userID).Scan(&exists)
			if err != nil {
				panic(err)
			}

			if exists {
				post.Disliked = true
			} else {
				post.Disliked = false
			}

		} else {
			post.Disliked = false
			post.Liked = false
		}

		posts = append(posts, post)
	}

	if err := contents.Err(); err != nil {
		log.Printf("Erreur de serveur: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return
	}

	/* 	request, err := db.Query("SELECT categories.* FROM categories JOIN categorieslikes ON categories.category_id = categorieslikes.category_id WHERE categorieslikes.user_id = ?", u.ID)
	   	if err != nil {
	   		log.Printf("Erreur de serveur: %v", err)
	   		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
	   		return
	   	} */

	request, err := db.Query("SELECT category_id, category_profile_picture, category_name, category_nbpost FROM categories")
	if err != nil {
		log.Printf("Erreur de serveur: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return
	}
	defer request.Close()

	for request.Next() {
		var category Category
		if err := request.Scan(&category.ID, &category.Base64Image, &category.Title, &category.NbPost); err != nil {
			log.Printf("Erreur de serveur: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return
		}
		categories = append(categories, category)
	}

	if err := contents.Err(); err != nil {
		log.Printf("Erreur de serveur: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return
	}

	data := struct {
		Posts      []Post
		Categories []Category
	}{
		Posts:      posts,
		Categories: categories,
	}

	tmpl, err := template.ParseFiles("post.html")
	if err != nil {
		log.Printf("Erreur de serveur: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return

	}
	tmpl.Execute(w, data)

}

func (u *User) Feed2(w http.ResponseWriter, r *http.Request) {

	var categories []Category

	/* 	posts = append(posts, Post{Title: "Post 1", Description: "This is the first post"})
	   	posts = append(posts, Post{Title: "Post 2", Description: "This is the second post"})
	*/
	db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
	if dbInitErr != nil {
		http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	var contents *sql.Rows

	if filterOrder == "recent" {
		request, err := db.Query("SELECT category_id, category_profile_picture, category_name, category_description FROM categories")
		if err != nil {
			log.Printf("Erreur de serveur: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return
		} else {
			contents = request
		}

	} else if filterOrder == "oldest" {
		request, err := db.Query("SELECT category_id, category_profile_picture, category_name, category_description FROM categories ORDER BY category_id DESC")
		if err != nil {
			log.Printf("Erreur de serveur: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return
		} else {
			contents = request
		}

	} else if filterOrder == "most-likes" {
		request, err := db.Query("SELECT category_id, category_profile_picture, category_name, category_description FROM categories ORDER BY category_nblike DESC")
		if err != nil {
			log.Printf("Erreur de serveur: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return
		}
		contents = request
	} else if filterOrder == "least-likes" {
		request, err := db.Query("SELECT category_id, category_profile_picture, category_name, category_description FROM categories ORDER BY category_nblike ASC")
		if err != nil {
			log.Printf("Erreur de serveur: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return
		}
		contents = request
	} else if filterOrder == "most-interactions" {
		request, err := db.Query("SELECT category_id, category_profile_picture, category_name, category_description FROM categories ORDER BY category_nbpost DESC")
		if err != nil {
			log.Printf("Erreur de serveur: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return
		}
		contents = request
	} else if filterOrder == "least-interactions" {
		request, err := db.Query("SELECT category_id, category_profile_picture, category_name, category_description FROM categories ORDER BY  category_nbcomment ASC")
		if err != nil {
			log.Printf("Erreur de serveur: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return
		}
		contents = request
	} else {
		request, err := db.Query("SELECT category_id, category_profile_picture, category_name, category_description FROM categories")
		if err != nil {
			log.Printf("Erreur de serveur: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return
		} else {
			contents = request
		}
	}

	defer contents.Close()

	for contents.Next() {
		var category Category
		if err := contents.Scan(&category.ID, &category.Base64Image, &category.Title, &category.Description); err != nil {
			log.Printf("Erreur de serveur: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return
		}
		categories = append(categories, category)
	}

	if err := contents.Err(); err != nil {
		log.Printf("Erreur de serveur: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return
	}

	/* 	request, err := db.Query("SELECT categories.* FROM categories JOIN categorieslikes ON categories.category_id = categorieslikes.category_id WHERE categorieslikes.user_id = ?", u.ID)
	   	if err != nil {
	   		log.Printf("Erreur de serveur: %v", err)
	   		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
	   		return
	   	} */

	var categoriesLiked []Category
	request, err := db.Query("SELECT category_id, category_profile_picture, category_name, category_nbpost FROM categories")
	if err != nil {
		log.Printf("Erreur de serveur: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return
	}
	defer request.Close()

	for request.Next() {
		var categoryLiked Category
		if err := request.Scan(&categoryLiked.ID, &categoryLiked.Base64Image, &categoryLiked.Title, &categoryLiked.NbPost); err != nil {
			log.Printf("Erreur de serveur: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return
		}
		categoriesLiked = append(categoriesLiked, categoryLiked)
	}

	if err := contents.Err(); err != nil {
		log.Printf("Erreur de serveur: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return
	}

	data := struct {
		CategoriesLiked []Category
		Categories      []Category
	}{
		CategoriesLiked: categoriesLiked,
		Categories:      categories,
	}

	tmpl, err := template.ParseFiles("category.html")
	if err != nil {
		log.Printf("Erreur de serveur: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return

	}
	tmpl.Execute(w, data)

}

func (u *User) createCategory(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "userSession")
	if err != nil {
		log.Printf("Erreur lors de la récupération de la session: %v", err)
		http.Error(w, "Erreur de session", http.StatusInternalServerError)
		return
	}

	_, ok := session.Values["userID"].(int)
	if !ok {
		http.Error(w, "You are not connected", http.StatusInternalServerError)
		return
	}
	db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")

	if dbInitErr != nil {
		http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
		return
	}

	err = r.ParseMultipartForm(20 << 20) // 20 MB max file size
	if err != nil {
		log.Printf("Erreur lors du parsing du formulaire: %v", err)
		http.Error(w, "Erreur lors du parsing du formulaire", http.StatusInternalServerError)
		return
	}
	r.ParseMultipartForm(20 << 20) // 20 MB max file size

	message := r.FormValue("category-description")

	title := r.FormValue("category-title")

	file, _, err := r.FormFile("category-attachment")
	if err != nil {
		http.Error(w, "Erreur lors de l'obtention du fichier", http.StatusBadRequest)
		return
	}

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, file); err != nil {
		http.Error(w, "Erreur lors de la lecture du fichier", http.StatusInternalServerError)
		return
	}
	fileBytes := buf.Bytes()

	stmt, err := db.Prepare("INSERT INTO categories(category_name, category_description, category_profile_picture) VALUES(?, ?, ?)")
	if err != nil {
		http.Error(w, "Erreur lors de la préparation de la requête", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()
	imageString := base64.StdEncoding.EncodeToString(fileBytes)

	_, err = stmt.Exec(title, message, imageString)
	if err != nil {
		http.Error(w, "Erreur lors de l'exécution de la requête", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "http://localhost:5500/", http.StatusSeeOther)

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
	http.Handle("/login/oauth", &app) // Utilisation d'&app pour gérer les routes OAuth
	http.Handle("/callback", &app)    // Utilisation d'&app pour gérer les callbacks OAuth
	http.Handle("/logout", new(User))
	http.Handle("/posts", new(User))
	http.Handle("/post", new(User))
	http.Handle("/user-profile", new(User))
	http.HandleFunc("/submit-report", submitReportHandler)
	http.HandleFunc("/view-reports", viewReportsHandler)
	http.HandleFunc("/delete-post", deletePostHandler)
	http.HandleFunc("/ignore-report", ignoreReportHandler)

	log.Fatal(http.ListenAndServe(":5500", nil))
}
func getUserIdFromRequest(r *http.Request) (int, error) {

	cookie, err := r.Cookie("user_id")
	if err != nil {
		return 0, err
	}
	id, err := strconv.Atoi(cookie.Value)
	if err != nil {
		return 0, err
	}
	return id, nil

}

func submitReportHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	var postID int
	var err error

	// Vérifier si post-id est disponible (version avec champ caché dans uniquePost.html)
	if postIDStr := r.FormValue("post-id"); postIDStr != "" {
		postID, err = strconv.Atoi(postIDStr)
		if err != nil {
			http.Error(w, "Invalid post ID", http.StatusBadRequest)
			return
		}
	} else {
		// Sinon, extraire l'ID du post à partir de post-url (version avec champ post-url dans index.html)
		postURL := r.FormValue("post-url")
		postID, err = extractPostIDFromURL(postURL)
		if err != nil {
			http.Error(w, "Invalid post ID", http.StatusBadRequest)
			return
		}
	}

	reason := r.FormValue("report-reason")
	comment := r.FormValue("report-comment")

	report := Report{
		PostID:  postID,
		Reason:  reason,
		Comment: comment,
		Status:  "active",
	}

	// Exemple de gestion des rapports (à adapter selon votre application)
	reportsLock.Lock()
	reports = append(reports, report)
	reportsLock.Unlock()

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Fonction pour extraire l'ID du post de l'URL
func extractPostIDFromURL(postURL string) (int, error) {
	u, err := url.Parse(postURL)
	if err != nil {
		return 0, err
	}

	idStr := u.Query().Get("id")
	postID, err := strconv.Atoi(idStr)
	if err != nil {
		return 0, err
	}

	return postID, nil
}

func viewReportsHandler(w http.ResponseWriter, r *http.Request) {
	// Récupérer l'ID de l'utilisateur depuis le cookie
	idUSER, err := getUserIdFromRequest(r)
	if err != nil {
		http.Error(w, "Erreur : utilisateur non connecté", http.StatusUnauthorized)
		return
	}

	// Charger les informations de l'utilisateur depuis la base de données
	var currentUser User
	err = currentUser.loadUserFromDB(idUSER)
	if err != nil {
		log.Printf("Erreur lors du chargement des informations de l'utilisateur: %v", err)
		http.Error(w, "Erreur lors de la récupération des informations de l'utilisateur", http.StatusInternalServerError)
		return
	}

	if currentUser.Role != "admin" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}

	tmpl, err := template.ParseFiles("viewReports.html")
	if err != nil {
		log.Printf("Erreur lors de l'analyse du template: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return
	}

	reportsLock.Lock()
	defer reportsLock.Unlock()

	// Préparer les données à envoyer au template
	type TemplateData struct {
		Username string
		Role     string
		Reports  []Report // Assurez-vous de passer vos rapports ici
	}

	data := TemplateData{
		Username: currentUser.Username,
		Role:     currentUser.Role,
		Reports:  reports, // Remplacez par votre slice de rapports
	}

	// Exécuter le template avec les données
	err = tmpl.Execute(w, data)
	if err != nil {
		log.Printf("Erreur lors de l'exécution du template: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return
	}
}

func deletePostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	postID, err := strconv.Atoi(r.FormValue("post-id"))
	if err != nil {
		http.Error(w, "Invalid post ID", http.StatusBadRequest)
		return
	}

	fmt.Printf("Suppression du post avec ID: %d\n", postID)

	// Supprimer le post de la base de données
	db, err := sql.Open("sqlite3", "./forumv3.db")
	if err != nil {
		http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Supprimer le post
	_, err = db.Exec("DELETE FROM posts WHERE posts_id = ?", postID)
	if err != nil {
		log.Printf("Erreur lors de la suppression du post: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return
	}

	// Supprimer les signalements associés
	reportsLock.Lock()
	for i, report := range reports {
		if report.PostID == postID {
			reports = append(reports[:i], reports[i+1:]...)
			break
		}
	}
	reportsLock.Unlock()

	http.Redirect(w, r, "/view-reports", http.StatusSeeOther)
}

func ignoreReportHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	postID, err := strconv.Atoi(r.FormValue("post-id"))
	if err != nil {
		http.Error(w, "Invalid post ID", http.StatusBadRequest)
		return
	}

	fmt.Printf("Ignorer le signalement pour le post avec ID: %d\n", postID)

	reportsLock.Lock()
	for i, report := range reports {
		if report.PostID == postID {
			reports[i].Status = "ignored"
			break
		}
	}
	reportsLock.Unlock()

	http.Redirect(w, r, "/view-reports", http.StatusSeeOther)
}
