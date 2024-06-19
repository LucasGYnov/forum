package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
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
)

// Encryption key for session cookies
var store = sessions.NewCookieStore([]byte("keySession"))

// Session cookie expiration time configuration (e.g., 1 hour)
const sessionExpiration = 1 * time.Hour

// RegisterHandler handles user registration
type RegisterHandler struct {
	db        *sql.DB
	dbInitErr error
}

// User represents a registered user
type User struct {
	ID          int
	Username    string
	Email       string
	Image       []byte
	Base64Image string
	Role        string
}

// Post represents a blog post
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

// Category represents a blog post category
type Category struct {
	ID          int
	Title       string
	NbPost      int
	Image       []byte
	Base64Image string
	Posts       []Post
	Description string
}

// Comment represents a comment on a blog post
type Comment struct {
	ID          int
	AuthorId    int
	AuthorName  string
	Description string
	Image       []byte
	Base64Image string
}

// Goauth represents Google OAuth user data structure
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

// Report represents a report on a blog post or comment
type Report struct {
	PostID  int
	Reason  string
	Comment string
	Status  string
}

var (
	reports     []Report   // Slice to hold reports
	reportsLock sync.Mutex // Mutex to synchronize access to reports slice

	jsonResp Goauth // Variable to hold Google OAuth response

	filterOrder   string // Variables for filtering
	filterType    string
	filterSubject string
	filterOther   string
)

func (u *User) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Retrieving the session named "userSession" from the store
	session, err := store.Get(r, "userSession")
	if err != nil {
		log.Printf("Error retrieving session: %v", err)
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	// Handling requests to the root path "/"
	if r.URL.Path == "/" {
		// Handling GET requests to "/"
		if r.Method == "GET" {
			// Parsing the HTML template file "index.html"
			tmpl, err := template.ParseFiles("index.html")
			if err != nil {
				log.Printf("Error parsing template index.html: %v", err)
				http.Error(w, "Server error", http.StatusInternalServerError)
				return
			}

			// Fetching categories from the database
			var categories []Category
			db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
			if dbInitErr != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}
			defer db.Close()

			request, err := db.Query("SELECT category_name FROM categories")
			if err != nil {
				log.Printf("Server error: %v", err)
				http.Error(w, "Server error", http.StatusInternalServerError)
				return
			}
			defer request.Close()

			// Iterating over the database query results to populate categories slice
			for request.Next() {
				var category Category
				if err := request.Scan(&category.Title); err != nil {
					log.Printf("Server error: %v", err)
					http.Error(w, "Server error", http.StatusInternalServerError)
					return
				}
				categories = append(categories, category)
			}

			// Data structure to pass to the template
			data := struct {
				Categories []Category
				User       *User
			}{
				Categories: categories,
				User:       u,
			}

			// Executing the HTML template with the data and writing to the response
			tmpl.Execute(w, data)
			return
		}

		// Handling POST requests to "/"
		if r.Method == "POST" {
			// Retrieving session again to ensure user is authenticated
			session, err := store.Get(r, "userSession")
			if err != nil {
				log.Printf("Error retrieving session: %v", err)
				http.Error(w, "Session error", http.StatusInternalServerError)
				return
			}

			// Extracting userID from session values
			userID, ok := session.Values["userID"].(int)
			if !ok {
				http.Error(w, "You are not connected", http.StatusInternalServerError)
				return
			}

			// Opening the database connection
			db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
			if dbInitErr != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}

			// Parsing the multipart form with a max file size of 20 MB
			err = r.ParseMultipartForm(20 << 20)
			if err != nil {
				log.Printf("Error parsing form: %v", err)
				http.Error(w, "Error parsing form", http.StatusInternalServerError)
				return
			}

			// Retrieving form values
			message := r.FormValue("post-message")
			title := r.FormValue("post-title")
			category := r.FormValue("post-subject")

			var categoryID int

			// Querying for category ID based on category name
			_ = db.QueryRow("SELECT category_id FROM categories WHERE category_name=?", category).Scan(&categoryID)

			// Retrieving file from the form
			file, _, err := r.FormFile("post-attachment")
			if err != nil {
				http.Error(w, "Error obtaining file", http.StatusBadRequest)
				return
			}

			// Reading the file into a buffer
			buf := bytes.NewBuffer(nil)
			if _, err := io.Copy(buf, file); err != nil {
				http.Error(w, "Error reading file", http.StatusInternalServerError)
				return
			}
			fileBytes := buf.Bytes()

			// Preparing the SQL statement to insert the post into the database
			stmt, err := db.Prepare("INSERT INTO posts(posts_title, posts_description, posts_profile_picture, category_id, category_name, user_id) VALUES(?, ?, ?, ?, ?, ?)")
			if err != nil {
				http.Error(w, "Error preparing statement", http.StatusInternalServerError)
				return
			}
			defer stmt.Close()

			// Encoding file contents to base64 for storage
			imageString := base64.StdEncoding.EncodeToString(fileBytes)

			// Executing the insert statement with post details
			_, err = stmt.Exec(title, message, imageString, categoryID, category, userID)
			if err != nil {
				http.Error(w, "Error executing statement", http.StatusInternalServerError)
				return
			}

			// Redirecting user to the root after successful post creation
			http.Redirect(w, r, "http://localhost:5500/", http.StatusSeeOther)
			return
		}
	}

	// Handling requests based on the path of the URL
	if path.Base(r.URL.Path) == "post" {
		// Handling GET requests to "/post"
		if r.Method == "GET" {
			u.postHandler(w, r) // Calls the postHandler method of user u to handle the request
		} else if r.Method == "POST" {
			u.createComment(w, r) // Calls the createComment method of user u to handle the request
		}
	}

	// Handling requests based on the path of the URL
	if path.Base(r.URL.Path) == "category" {
		// Handling GET requests to "/category"
		if r.Method == "GET" {
			categoryHandler(w, r) // Calls the categoryHandler function to handle the request
		}
	}

	// Handling requests based on the path of the URL
	if path.Base(r.URL.Path) == "viewprofile" {
		// Handling GET requests to "/viewprofile"
		if r.Method == "GET" {
			u.viewProfileHandler(w, r) // Calls the viewProfileHandler method of user u to handle the request
		}
	}

	// Handling requests to "/like"
	if r.URL.Path == "/like" {
		// Handling POST requests to "/like"
		if r.Method == "POST" {
			fmt.Print("id user")
			fmt.Print(u.ID) // Printing the user ID

			dataType := r.FormValue("type") // Getting the type of data (post or category)

			// Handling likes for posts
			if dataType == "post" {
				postID := r.FormValue("post_id")
				postStatus := r.FormValue("isLiked")

				// Opening the database connection
				db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
				if dbInitErr != nil {
					http.Error(w, "Database error", http.StatusInternalServerError)
					return
				}

				// Inserting or deleting like based on postStatus value
				if postStatus == "false" {
					_, err = db.Exec("INSERT INTO postslikes (user_id, post_id) VALUES (?, ?)", u.ID, postID)
					if err != nil {
						log.Printf("Server error: %v", err)
						http.Error(w, "Server error", http.StatusInternalServerError)
						return
					}
				} else {
					_, err = db.Exec("DELETE FROM postslikes WHERE user_id = ? AND post_id = ?", u.ID, postID)
					if err != nil {
						log.Printf("Server error: %v", err)
						http.Error(w, "Server error", http.StatusInternalServerError)
						return
					}
				}

				// Handling likes for categories
			} else if dataType == "category" {
				categoryID := r.FormValue("category_id")
				categoryStatus := r.FormValue("isLiked")

				// Opening the database connection
				db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
				if dbInitErr != nil {
					http.Error(w, "Database error", http.StatusInternalServerError)
					return
				}

				// Inserting or deleting like based on categoryStatus value
				if categoryStatus == "false" {
					_, err = db.Exec("INSERT INTO categorieslikes (user_id, category_id) VALUES (?, ?)", u.ID, categoryID)
					if err != nil {
						log.Printf("Server error: %v", err)
						http.Error(w, "Server error", http.StatusInternalServerError)
						return
					}
				} else {
					_, err = db.Exec("DELETE FROM categorieslikes WHERE user_id = ? AND category_id = ?", u.ID, categoryID)
					if err != nil {
						log.Printf("Server error: %v", err)
						http.Error(w, "Server error", http.StatusInternalServerError)
						return
					}
				}
			}
		}
	}

	// Handling requests to "/apply-filters"
	if r.URL.Path == "/apply-filters" {
		// Handling POST requests to "/apply-filters"
		if r.Method == "POST" {
			filterOrder = r.FormValue("filter-order")
			filterType = r.FormValue("filter-type")
			filterSubject = r.FormValue("filter-subject")
			filterOther = r.FormValue("filter-other")

			// Redirecting to "/posts" after applying filters
			http.Redirect(w, r, "/posts", http.StatusSeeOther)
		}
	}

	// Handling requests to "/apply-filters-category"
	if r.URL.Path == "/apply-filters-category" {
		// Handling POST requests to "/apply-filters-category"
		if r.Method == "POST" {
			filterOrder = r.FormValue("filter-order")
			filterType = r.FormValue("filter-type")
			filterSubject = r.FormValue("filter-subject")
			filterOther = r.FormValue("filter-other")

			// Redirecting to "/categories" after applying filters
			http.Redirect(w, r, "/categories", http.StatusSeeOther)
		}
	}

	// Handling requests to "/submit-evaluation"
	if r.URL.Path == "/submit-evaluation" {
		// Handling POST requests to "/submit-evaluation"
		if r.Method == "POST" {
			// Retrieving session information from the request
			session, err := store.Get(r, "userSession")
			if err != nil {
				log.Printf("Error retrieving session: %v", err)
				http.Error(w, "Session error", http.StatusInternalServerError)
				return
			}

			// Checking if userID exists in the session
			userID, ok := session.Values["userID"].(int)
			if ok && userID > 0 {
				// Retrieving form values for evaluation
				evaluationDislike := r.FormValue("evaluationDislike")
				evaluationLike := r.FormValue("evaluationLike")
				postID := r.FormValue("post_id")

				// Handling dislike evaluation
				if evaluationDislike == "" {
					// Opening database connection
					db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
					if dbInitErr != nil {
						http.Error(w, "Database error", http.StatusInternalServerError)
						return
					}
					defer db.Close()

					// Checking if the user has already disliked the post
					var exists bool
					query := "SELECT EXISTS(SELECT 1 FROM postsdislikes WHERE post_id = ? AND user_id = ?)"
					err = db.QueryRow(query, postID, userID).Scan(&exists)
					if err != nil {
						panic(err)
					}

					// If user has disliked the post, remove dislike and update post's dislike count
					if exists {
						_, err = db.Exec("DELETE FROM postsdislikes WHERE user_id = ? AND post_id = ?", userID, postID)
						if err != nil {
							log.Printf("Server error: %v", err)
							http.Error(w, "Server error", http.StatusInternalServerError)
							return
						}
						_, err = db.Exec("UPDATE posts SET posts_nbdislike = posts_nbdislike - 1 WHERE posts_id = ?", postID)
						if err != nil {
							log.Printf("Server error: %v", err)
							http.Error(w, "Server error", http.StatusInternalServerError)
							return
						}
					}
				}

				// Handling like evaluation
				if evaluationLike == "" {
					// Opening database connection
					db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
					if dbInitErr != nil {
						http.Error(w, "Database error", http.StatusInternalServerError)
						return
					}
					defer db.Close()

					// Checking if the user has already liked the post
					var exists bool
					query := "SELECT EXISTS(SELECT 1 FROM postslikes WHERE post_id = ? AND user_id = ?)"
					err = db.QueryRow(query, postID, userID).Scan(&exists)
					if err != nil {
						panic(err)
					}

					// If user has liked the post, remove like and update post's like count
					if exists {
						_, err = db.Exec("DELETE FROM postslikes WHERE user_id = ? AND post_id = ?", userID, postID)
						if err != nil {
							log.Printf("Server error: %v", err)
							http.Error(w, "Server error", http.StatusInternalServerError)
							return
						}
						_, err = db.Exec("UPDATE posts SET posts_nblike = posts_nblike - 1 WHERE posts_id = ?", postID)
						if err != nil {
							log.Printf("Server error: %v", err)
							http.Error(w, "Server error", http.StatusInternalServerError)
							return
						}
					}

					// If user chose to like the post, insert like and update post's like count
					if evaluationLike == "like" {
						_, err = db.Exec("INSERT INTO postslikes (user_id, post_id) VALUES (?, ?)", userID, postID)
						if err != nil {
							log.Printf("Server error: %v", err)
							http.Error(w, "Server error", http.StatusInternalServerError)
							return
						}
						_, err = db.Exec("UPDATE posts SET posts_nblike = posts_nblike + 1 WHERE posts_id = ?", postID)
						if err != nil {
							log.Printf("Server error: %v", err)
							http.Error(w, "Server error", http.StatusInternalServerError)
							return
						}

						// Checking if the post was previously disliked by the user
						var exists bool
						query := "SELECT EXISTS(SELECT 1 FROM postsdislikes WHERE post_id = ? AND user_id = ?)"
						err = db.QueryRow(query, postID, userID).Scan(&exists)
						if err != nil {
							panic(err)
						}

						// If post was disliked, remove dislike and update post's dislike count
						if exists {
							_, err = db.Exec("DELETE FROM postsdislikes WHERE user_id = ? AND post_id = ?", userID, postID)
							if err != nil {
								log.Printf("Server error: %v", err)
								http.Error(w, "Server error", http.StatusInternalServerError)
								return
							}
							_, err = db.Exec("UPDATE posts SET posts_nbdislike = posts_nbdislike - 1 WHERE posts_id = ?", postID)
							if err != nil {
								log.Printf("Server error: %v", err)
								http.Error(w, "Server error", http.StatusInternalServerError)
								return
							}
						}
					}

					// If user chose to dislike the post, insert dislike and update post's dislike count
					if evaluationDislike == "dislike" {
						_, err = db.Exec("INSERT INTO postsdislikes (user_id, post_id) VALUES (?, ?)", userID, postID)
						if err != nil {
							log.Printf("Server error: %v", err)
							http.Error(w, "Server error", http.StatusInternalServerError)
							return
						}
						_, err = db.Exec("UPDATE posts SET posts_nbdislike = posts_nbdislike + 1 WHERE posts_id = ?", postID)
						if err != nil {
							log.Printf("Server error: %v", err)
							http.Error(w, "Server error", http.StatusInternalServerError)
							return
						}

						// Checking if the post was previously liked by the user
						var exists bool
						query := "SELECT EXISTS(SELECT 1 FROM postslikes WHERE post_id = ? AND user_id = ?)"
						err = db.QueryRow(query, postID, userID).Scan(&exists)
						if err != nil {
							panic(err)
						}

						// If post was liked, remove like and update post's like count
						if exists {
							_, err = db.Exec("DELETE FROM postslikes WHERE user_id = ? AND post_id = ?", userID, postID)
							if err != nil {
								log.Printf("Server error: %v", err)
								http.Error(w, "Server error", http.StatusInternalServerError)
								return
							}
							_, err = db.Exec("UPDATE posts SET posts_nblike = posts_nblike - 1 WHERE posts_id = ?", postID)
							if err != nil {
								log.Printf("Server error: %v", err)
								http.Error(w, "Server error", http.StatusInternalServerError)
								return
							}
						}
					}
				}
			} else {
				http.Error(w, "You are not connected", http.StatusInternalServerError)
			}
		}
	}

	// Handling requests to "/signin"
	if r.URL.Path == "/signin" {
		// Handling GET requests to "/signin"
		if r.Method == "GET" {
			tmpl, err := template.ParseFiles("signin.html")
			if err != nil {
				http.Error(w, "Server error", http.StatusInternalServerError)
				return
			}
			tmpl.Execute(w, nil) // Executing the template to render the "signin.html" page
			return
		} else if r.Method == "POST" {
			u.processRegistration(w, r) // Calling the processRegistration method of user u to handle POST request
			return
		}
	}

	// Handling requests to "/login"
	if r.URL.Path == "/login" {
		// Handling GET requests to "/login"
		if r.Method == "GET" {
			// Verify if user is already connected by checking session
			session, err := store.Get(r, "userSession")
			if err != nil {
				log.Printf("Error retrieving session: %v", err)
				http.Error(w, "Session error", http.StatusInternalServerError)
				return
			}

			// Check if userID exists in session; if not, show login page
			_, ok := session.Values["userID"].(int)
			if !ok {
				tmpl, err := template.ParseFiles("login.html")
				if err != nil {
					http.Error(w, "Server error", http.StatusInternalServerError)
					return
				}
				tmpl.Execute(w, u) // Execute the login.html template with user data 'u'
				return
			} else {
				http.Redirect(w, r, "/profile", http.StatusSeeOther) // Redirect to "/profile" if user is already logged in
			}

		} else if r.Method == "POST" {
			u.processLogin(w, r) // Call the processLogin method of user u to handle POST request for login
			return
		}
	}

	// Handling requests to "/profile"
	if r.URL.Path == "/profile" {
		// Handling GET requests to "/profile"
		if r.Method == "GET" {
			// Check if user is authenticated (userID exists in session)
			if userID, ok := session.Values["userID"].(int); ok {
				u.loadUserFromDB(userID) // Load user data from database based on userID
				u.handleUser(w, r)       // Handle user request
				return
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther) // Redirect to "/login" if user is not authenticated
			}

		} else if r.Method == "POST" {
			http.Redirect(w, r, "/logout", http.StatusSeeOther) // Redirect to "/logout" for POST requests to "/profile"
			return
		}
	}

	// Handling requests to "/submit-email"
	if r.URL.Path == "/submit-email" {
		// Handling POST requests to "/submit-email"
		if r.Method == "POST" {
			newEmail := r.FormValue("newEmail") // Retrieve new email from form data

			u.Email = newEmail // Update user's email in-memory

			// Retrieve session to update userEmail in session
			session, err := store.Get(r, "userSession")
			if err != nil {
				log.Printf("Error retrieving session: %v", err)
				http.Error(w, "Session error", http.StatusInternalServerError)
				return
			}

			session.Values["userEmail"] = newEmail // Update userEmail in session

			err = session.Save(r, w) // Save updated session
			if err != nil {
				log.Printf("Error saving session: %v", err)
				http.Error(w, "Error saving session", http.StatusInternalServerError)
				return
			}

			// Update user's email in the database
			db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
			if dbInitErr != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}
			defer db.Close()

			stmt, err := db.Prepare("UPDATE users SET email = ? WHERE user_id = ?")
			if err != nil {
				http.Error(w, "Error preparing query", http.StatusInternalServerError)
				return
			}
			defer stmt.Close()

			userID, ok := session.Values["userID"].(int)
			if !ok {
				http.Error(w, "You are not connected", http.StatusInternalServerError)
				return
			}

			_, err = stmt.Exec(newEmail, userID) // Execute update query
			if err != nil {
				http.Error(w, "Error executing query", http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, "/profile", http.StatusSeeOther) // Redirect to "/profile" after email update
		}
	}

	// Handling requests to "/submit-password"
	if r.URL.Path == "/submit-password" {
		// Handling POST requests to "/submit-password"
		if r.Method == "POST" {
			r.ParseMultipartForm(20 << 20) // Parse multipart form with max file size of 20 MB

			// Retrieve new and old passwords from form data
			newPassword := r.FormValue("newPassword")
			oldPassword := r.FormValue("oldPassword")

			// Retrieve session to get userID and userEmail
			session, err := store.Get(r, "userSession")
			if err != nil {
				log.Printf("Error retrieving session: %v", err)
				http.Error(w, "Session error", http.StatusInternalServerError)
				return
			}

			// Open database connection
			db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
			if dbInitErr != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}
			defer db.Close()

			// Prepare SQL statement to update user password
			stmt, err := db.Prepare("UPDATE users SET password = ? WHERE user_id = ?")
			if err != nil {
				http.Error(w, "Error preparing query", http.StatusInternalServerError)
				return
			}
			defer stmt.Close()

			// Retrieve userID from session
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

			// Verify old password
			var verifPassword string
			err = db.QueryRow("SELECT password FROM users WHERE email=? AND password=?", userEmail, oldPassword).Scan(&verifPassword)
			if err != nil {
				http.Error(w, "Error querying database", http.StatusInternalServerError)
				return
			}

			// If old password does not match, return error
			if oldPassword != verifPassword {
				http.Error(w, "Wrong password", http.StatusNotFound)
				return
			}

			// Execute update query to set new password
			_, err = stmt.Exec(newPassword, userID)
			if err != nil {
				http.Error(w, "Error executing query", http.StatusInternalServerError)
				return
			}

			// Redirect to "/profile" after password update
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
		}
	}

	// Handling requests to "/submit-picture"
	if r.URL.Path == "/submit-picture" {
		// Handling POST requests to "/submit-picture"
		if r.Method == "POST" {
			r.ParseMultipartForm(20 << 20) // Parse multipart form with max file size of 20 MB

			// Retrieve uploaded image file
			file, _, err := r.FormFile("newImage")
			if err != nil {
				http.Error(w, "Error getting file", http.StatusBadRequest)
				return
			}
			defer file.Close()

			// Read the file into a byte slice
			buf := bytes.NewBuffer(nil)
			if _, err := io.Copy(buf, file); err != nil {
				http.Error(w, "Error reading file", http.StatusInternalServerError)
				return
			}
			newPicture := buf.Bytes()

			// Retrieve session to update and save session data
			session, err := store.Get(r, "userSession")
			if err != nil {
				log.Printf("Error retrieving session: %v", err)
				http.Error(w, "Session error", http.StatusInternalServerError)
				return
			}

			err = session.Save(r, w)
			if err != nil {
				log.Printf("Error saving session: %v", err)
				http.Error(w, "Error saving session", http.StatusInternalServerError)
				return
			}

			// Open database connection
			db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
			if dbInitErr != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}
			defer db.Close()

			// Prepare SQL statement to update user profile picture
			stmt, err := db.Prepare("UPDATE users SET profile_picture = ? WHERE user_id = ?")
			if err != nil {
				http.Error(w, "Error preparing query", http.StatusInternalServerError)
				return
			}
			defer stmt.Close()

			// Retrieve userID from session
			userID, ok := session.Values["userID"].(int)
			if !ok {
				http.Error(w, "You are not connected", http.StatusInternalServerError)
				return
			}

			// Execute update query to set new profile picture
			_, err = stmt.Exec(newPicture, userID)
			if err != nil {
				http.Error(w, "Error executing query", http.StatusInternalServerError)
				return
			}

			// Redirect to "/profile" after updating profile picture
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
		}
	}

	// Handling requests to "/submit-username"
	if r.URL.Path == "/submit-username" {
		// Handling POST requests to "/submit-username"
		if r.Method == "POST" {
			// Retrieve new username from form data
			newUsername := r.FormValue("newUsername")

			// Retrieve session to update userName and save session data
			session, err := store.Get(r, "userSession")
			if err != nil {
				log.Printf("Error retrieving session: %v", err)
				http.Error(w, "Session error", http.StatusInternalServerError)
				return
			}

			session.Values["userName"] = newUsername

			err = session.Save(r, w)
			if err != nil {
				log.Printf("Error saving session: %v", err)
				http.Error(w, "Error saving session", http.StatusInternalServerError)
				return
			}

			// Open database connection
			db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
			if dbInitErr != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}
			defer db.Close()

			// Prepare SQL statement to update user username
			stmt, err := db.Prepare("UPDATE users SET username = ? WHERE user_id = ?")
			if err != nil {
				http.Error(w, "Error preparing query", http.StatusInternalServerError)
				return
			}
			defer stmt.Close()

			// Retrieve userID from session
			userID, ok := session.Values["userID"].(int)
			if !ok {
				http.Error(w, "You are not connected", http.StatusInternalServerError)
				return
			}

			// Execute update query to set new username
			_, err = stmt.Exec(newUsername, userID)
			if err != nil {
				http.Error(w, "Error executing query", http.StatusInternalServerError)
				return
			}

			// Redirect to "/profile" after updating username
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
		}
	}

	// Handling requests to "/logout"
	if r.URL.Path == "/logout" {
		// Handling GET requests to "/logout"
		if r.Method == "GET" {
			// Delete all session values and set MaxAge to -1 to invalidate session
			for key := range session.Values {
				delete(session.Values, key)
			}
			session.Options.MaxAge = -1

			// Save session to apply changes
			err = session.Save(r, w)
			if err != nil {
				http.Error(w, "Error saving session", http.StatusInternalServerError)
				return
			}

			// Process logout by calling u.processLogout
			u.processLogout(w, r)
			return
		}
		// Handling POST requests to "/logout"
		if r.Method == "POST" {
			http.Redirect(w, r, "/login", http.StatusSeeOther) // Redirect to "/login" after logout
			return
		}
	}

	// Handling requests to "/posts"
	if r.URL.Path == "/posts" {
		// Handling GET requests to "/posts"
		if r.Method == "GET" {
			u.Feed(w, r) // Call u.Feed to handle the request
			return
		}
	}

	// Handling requests to "/categories"
	if r.URL.Path == "/categories" {
		// Handling GET requests to "/categories"
		if r.Method == "GET" {
			u.Feed2(w, r) // Call u.Feed2 to handle the request
			return
		}
	}

	// Handling requests to "/category"
	if r.URL.Path == "/category" {
		// Handling POST requests to "/category"
		if r.Method == "POST" {
			u.createCategory(w, r) // Call u.createCategory to handle the request
			return
		}
	}

	// Handling requests to "/user-profile"
	if r.URL.Path == "/user-profile" {
		// Handling GET requests to "/user-profile"
		if r.Method == "GET" {
			tmpl, err := template.ParseFiles("user-profile.html")
			if err != nil {
				http.Error(w, "Server error", http.StatusInternalServerError)
				return
			}
			tmpl.Execute(w, u) // Execute user-profile.html template with user data 'u'
			return
		}
	}

}

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

	message := r.FormValue("message")

	file, _, err := r.FormFile("response-attachment")

	if err == nil {
		buf := bytes.NewBuffer(nil)
		if _, err := io.Copy(buf, file); err != nil {
			http.Error(w, "Erreur lors de la lecture du fichier", http.StatusInternalServerError)
			return
		}
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

	db, erro := sql.Open("sqlite3", "./forumv3.db")
	if erro != nil {
		return
	}
	defer db.Close()

	erro = db.QueryRow("SELECT username, email, profile_picture FROM users WHERE user_id=?", u.ID).Scan(&u.Username, &u.Email, &u.Image)
	if erro != nil {
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

func (u *User) viewProfileHandler(w http.ResponseWriter, r *http.Request) {
	var username string
	var image []byte
	var posts []Post
	var contents *sql.Rows

	tmpl, err := template.ParseFiles("user-profile.html")
	if err != nil {
		log.Printf("Erreur de serveur: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return
	}
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	user_id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	db, erro := sql.Open("sqlite3", "./forumv3.db")
	if erro != nil {
		return
	}
	defer db.Close()

	erro = db.QueryRow("SELECT username, profile_picture FROM users WHERE user_id=?", user_id).Scan(&username, &image)
	if erro != nil {
		return
	}

	request, err := db.Query("SELECT posts_title, posts_description, category_name, posts_nblike FROM posts WHERE user_id = ?", user_id)
	if err != nil {
		log.Printf("Erreur de serveur: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return
	} else {
		contents = request
	}

	defer contents.Close()

	for contents.Next() {
		var post Post
		if err := contents.Scan(&post.Title, &post.Description, &post.CategoryName, &post.Nblike); err != nil {
			log.Printf("Erreur de serveur: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return
		}
		posts = append(posts, post)
	}

	data := struct {
		Username    string
		Image       []byte
		Base64Image string
		Posts       []Post
	}{
		Username:    username,
		Image:       image,
		Base64Image: base64.StdEncoding.EncodeToString(image),
		Posts:       posts,
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

	fs := http.FileServer(http.Dir("public"))
	http.Handle("/public/", http.StripPrefix("/public/", fs))

	http.Handle("/", new(User))
	http.Handle("/signin", new(User))
	http.Handle("/profile", new(User))
	http.Handle("/login", new(User))
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
