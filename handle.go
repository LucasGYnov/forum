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
	// Get the post ID from the request query parameters
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Convert ID from string to integer
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Load post details from the database
	var post Post
	db, err := sql.Open("sqlite3", "./forumv3.db")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Query to retrieve post details by ID
	err = db.QueryRow("SELECT posts_title, posts_description, posts_profile_picture, category_name, posts_nblike, posts_nbdislike FROM posts WHERE posts_id=?", id).Scan(&post.Title, &post.Description, &post.Base64Image, &post.CategoryName, &post.Nblike, &post.Nbdislike)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "No post found with this ID", http.StatusNotFound)
			return
		}
		log.Printf("Error retrieving post information: %v", err)
		http.Error(w, "Error retrieving post information", http.StatusInternalServerError)
		return
	}
	post.ID = id
	post.Comments = getComments(w, r, id) // Retrieve comments for the post

	// Retrieve session to check user's like and dislike status for the post
	session, err := store.Get(r, "userSession")
	if err != nil {
		log.Printf("Error retrieving session: %v", err)
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	// Check if userID exists in session.Values
	userID, ok := session.Values["userID"].(int)
	if !ok {
		post.Liked = false
		post.Disliked = false
	} else {
		var exists bool

		// Check if user has liked the post
		query := "SELECT EXISTS(SELECT 1 FROM postslikes WHERE post_id = ? AND user_id = ?)"
		err = db.QueryRow(query, post.ID, userID).Scan(&exists)
		if err != nil {
			panic(err)
		}
		post.Liked = exists

		// Check if user has disliked the post
		query = "SELECT EXISTS(SELECT 1 FROM postsdislikes WHERE post_id = ? AND user_id = ?)"
		err = db.QueryRow(query, post.ID, userID).Scan(&exists)
		if err != nil {
			panic(err)
		}
		post.Disliked = exists
	}

	// Prepare data to pass to the template
	tmpl, err := template.ParseFiles("uniquePost.html")
	if err != nil {
		log.Printf("Error parsing template: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Check if the user is logged in and determine if they have admin/moderator privileges
	idUSER, err := getUserIdFromRequest(r)
	if err != nil {
		data := struct {
			Post    Post
			IsAdmin bool
		}{
			Post:    post,
			IsAdmin: false,
		}
		tmpl.Execute(w, data) // Execute the template with the data
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
		tmpl.Execute(w, data) // Execute the template with the data
	}
}

func categoryHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve the 'id' parameter from the URL query string
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Convert 'id' from string to integer
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Initialize a Category struct to store category information
	var category Category

	// Open a connection to the SQLite database
	db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
	if dbInitErr != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Query to fetch category details by 'id'
	err = db.QueryRow("SELECT category_name, category_description, category_profile_picture FROM categories WHERE category_id=?", id).
		Scan(&category.Title, &category.Description, &category.Base64Image)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "No category found with this ID", http.StatusNotFound)
			return
		}
		log.Printf("Error retrieving category information: %v", err)
		http.Error(w, "Error retrieving category information", http.StatusInternalServerError)
		return
	}

	// Retrieve posts associated with the category
	category.Posts = getPosts(w, r, id)

	// Parse the template file 'uniqueCategory.html'
	tmpl, err := template.ParseFiles("uniqueCategory.html")
	if err != nil {
		log.Printf("Template parsing error: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Execute the template with the 'category' data and write the result to the response writer
	tmpl.Execute(w, category)
}

func (u *User) createComment(w http.ResponseWriter, r *http.Request) {
	// Retrieve session information for the current user
	session, err := store.Get(r, "userSession")
	if err != nil {
		log.Printf("Error retrieving session: %v", err)
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	// Extract user details from session
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

	// Populate User struct fields with session data
	u.ID = userID
	u.Email = userEmail
	u.Base64Image = userProfilePicture
	u.Username = userName

	// Retrieve 'id' parameter from URL query string
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Convert 'id' to integer
	post_id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Open connection to SQLite database
	db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
	if dbInitErr != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Parse form data (20 MB max file size)
	err = r.ParseMultipartForm(20 << 20)
	if err != nil {
		log.Printf("Error parsing form: %v", err)
		http.Error(w, "Form parsing error", http.StatusInternalServerError)
		return
	}

	// Extract comment message from form data
	message := r.FormValue("message")

	// Retrieve optional file attachment
	file, _, err := r.FormFile("response-attachment")
	if err != nil {
		// Handle error if no file uploaded
		buf := bytes.NewBuffer(nil)
		if _, err := io.Copy(buf, file); err != nil {
			http.Error(w, "Erreur lors de la lecture du fichier", http.StatusInternalServerError)
			return
		}
	}

	// Insert comment into the database
	stmt, err := db.Prepare("INSERT INTO comments2(comments2_text, comments2_post_id, comments2_author_id) VALUES(?, ?, ?)")
	if err != nil {
		http.Error(w, "Error preparing statement", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(message, post_id, u.ID)
	if err != nil {
		http.Error(w, "Error executing query", http.StatusInternalServerError)
		return
	}

	// Update post's comment count in the database
	_, err = db.Exec("UPDATE posts SET posts_nbcomment = posts_nbcomment + 1 WHERE posts_id = ?", post_id)
	if err != nil {
		log.Printf("Server error: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Redirect user to the post's URL after successful comment submission
	url := fmt.Sprintf("http://localhost:5500/post?id=%v", post_id)
	http.Redirect(w, r, url, http.StatusSeeOther)
}

func (u *User) processLogin(w http.ResponseWriter, r *http.Request) {
	// Open a connection to the SQLite database
	db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
	if dbInitErr != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Parse form data (20 MB max file size)
	r.ParseMultipartForm(20 << 20)

	// Retrieve email and password from the login form
	email := r.FormValue("email")
	password := r.FormValue("password")
	motDePasse := []byte(password) // Convert password to bytes

	var mdpHache string
	// Retrieve hashed password from the database for the provided email
	db.QueryRow("SELECT password FROM users WHERE email=? AND auth_provider = 'website'", email).Scan(&mdpHache)

	// Compare the provided password with the hashed password from the database
	err := bcrypt.CompareHashAndPassword([]byte(mdpHache), motDePasse)
	if err != nil {
		// If passwords do not match, return unauthorized error
		http.Error(w, "Incorrect password", http.StatusUnauthorized)
		return
	}

	// Retrieve user information from the database based on email and hashed password
	err = db.QueryRow("SELECT user_id, username, email FROM users WHERE email=? AND password=? AND auth_provider = 'website'", email, mdpHache).Scan(&u.ID, &u.Username, &u.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "No user found with this ID", http.StatusNotFound)
			return
		}
		log.Printf("Error retrieving user information: %v", err)
		http.Error(w, "Error retrieving user information", http.StatusInternalServerError)
		return
	}

	// Save user ID, email, profile picture, username, and role in the session
	session, err := store.Get(r, "userSession")
	if err != nil {
		log.Printf("Error retrieving session: %v", err)
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	session.Values["userID"] = u.ID
	session.Values["userEmail"] = u.Email
	session.Values["userProfile_Picture"] = u.Base64Image
	session.Values["userName"] = u.Username
	session.Values["role"] = u.Role

	// Define session options (expiration, path, HttpOnly)
	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   int(sessionExpiration.Seconds()), // Duration in seconds
		HttpOnly: true,                             // Security reasons
	}

	// Set a cookie with the user's ID (same expiration as session)
	cookie := &http.Cookie{
		Name:     "user_id",
		Value:    strconv.Itoa(u.ID),
		Path:     "/",
		MaxAge:   int(sessionExpiration.Seconds()),
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)

	// Save the session
	err = session.Save(r, w)
	if err != nil {
		log.Printf("Error saving session: %v", err)
		http.Error(w, "Error saving session", http.StatusInternalServerError)
		return
	}

	// Redirect user to the profile page after successful login
	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

func downloadImage(url string) ([]byte, error) {
	// Perform a GET request to download the image
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check the response status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch image: %s", resp.Status)
	}

	// Read the response body into a []byte variable
	imageData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Return the image content
	return imageData, nil
}

func (u *User) processRegistrationGoogle(w http.ResponseWriter, r *http.Request, email string, username string, picture string) {
	// Open the SQLite database connection
	db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
	if dbInitErr != nil {
		http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// URL of the profile picture to download
	profilePictureURL := picture

	// Download the image and store it temporarily
	tempFile, err := downloadImage(profilePictureURL)
	if err != nil {
		fmt.Printf("Error downloading image: %v\n", err)
		return
	}

	// Insert the user into the database
	stmt, err := db.Prepare("INSERT INTO users(username, email, profile_picture, auth_provider) VALUES(?, ?, ?, ?)")
	if err != nil {
		http.Error(w, "Erreur lors de la préparation de la requête", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	// Execute the prepared statement to insert user data
	_, err = stmt.Exec(username, email, tempFile, "google")
	if err != nil {
		http.Error(w, "Erreur lors de l'exécution de la requête", http.StatusInternalServerError)
		return
	}

	// Redirect to the login page after successful registration
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (u *User) processRegistration(w http.ResponseWriter, r *http.Request) {
	// Open a connection to the SQLite database
	db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
	if dbInitErr != nil {
		http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Parse the multipart form with a max file size of 20 MB
	r.ParseMultipartForm(20 << 20)

	// Extract form values from the request
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	// Convert the plain-text password to bytes
	motDePasse := []byte(password)

	// Generate a salt and hash the password with the salt using bcrypt
	motDePasseHache, err := bcrypt.GenerateFromPassword(motDePasse, bcrypt.DefaultCost)
	if err != nil {
		fmt.Println(err)
		return
	}
	// Convert the hashed password back to string for storage
	password = string(motDePasseHache)

	// Retrieve the profile picture file from the form data
	file, _, err := r.FormFile("profile_picture")
	if err != nil {
		http.Error(w, "Erreur lors de l'obtention du fichier", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Read the file into a buffer
	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, file); err != nil {
		http.Error(w, "Erreur lors de la lecture du fichier", http.StatusInternalServerError)
		return
	}
	fileBytes := buf.Bytes()

	// Prepare an SQL statement to insert the user into the database
	stmt, err := db.Prepare("INSERT INTO users(username, email, password, profile_picture, auth_provider) VALUES(?, ?, ?, ?, ?)")
	if err != nil {
		http.Error(w, "Erreur lors de la préparation de la requête", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	// Execute the prepared SQL statement to insert user data into the database
	_, err = stmt.Exec(username, email, password, fileBytes, "website")
	if err != nil {
		http.Error(w, "Erreur lors de l'exécution de la requête", http.StatusInternalServerError)
		return
	}

	// Redirect to the login page after successful registration
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (u *User) loadUserFromDB(userID int) error {
	// Open a connection to the SQLite database
	db, err := sql.Open("sqlite3", "./forumv3.db")
	if err != nil {
		return err
	}
	defer db.Close()

	// Query the database to fetch username and role based on user ID
	err = db.QueryRow("SELECT username, role FROM users WHERE user_id=?", userID).Scan(&u.Username, &u.Role)
	if err != nil {
		return err
	}

	// Set the user's ID
	u.ID = userID
	return nil
}

func (u *User) handleUser(w http.ResponseWriter, r *http.Request) {
	// Parse the HTML template file
	tmpl, err := template.ParseFiles("usertest.html")
	if err != nil {
		log.Printf("Erreur de serveur: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return
	}

	// Open a connection to the SQLite database
	db, erro := sql.Open("sqlite3", "./forumv3.db")
	if erro != nil {
		return
	}
	defer db.Close()

	// Query the database to fetch username, email, and profile picture based on user ID
	erro = db.QueryRow("SELECT username, email, profile_picture FROM users WHERE user_id=?", u.ID).Scan(&u.Username, &u.Email, &u.Image)
	if erro != nil {
		return
	}

	// Encode the profile picture to Base64 for embedding in HTML
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

	// Execute the HTML template with the fetched data
	tmpl.Execute(w, data)
}

func (u *User) viewProfileHandler(w http.ResponseWriter, r *http.Request) {
	var username string
	var image []byte
	var posts []Post
	var contents *sql.Rows

	// Parse the HTML template file
	tmpl, err := template.ParseFiles("user-profile.html")
	if err != nil {
		log.Printf("Erreur de serveur: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return
	}

	// Extract user ID from the URL query parameters
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Convert user ID from string to integer
	user_id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Open a connection to the SQLite database
	db, erro := sql.Open("sqlite3", "./forumv3.db")
	if erro != nil {
		return
	}
	defer db.Close()

	// Query the database to fetch username and profile picture based on user ID
	erro = db.QueryRow("SELECT username, profile_picture FROM users WHERE user_id=?", user_id).Scan(&username, &image)
	if erro != nil {
		return
	}

	// Query the database to fetch posts associated with the user
	request, err := db.Query("SELECT posts_title, posts_description, category_name, posts_nblike FROM posts WHERE user_id = ?", user_id)
	if err != nil {
		log.Printf("Erreur de serveur: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return
	} else {
		contents = request
	}
	defer contents.Close()

	// Iterate through the fetched posts and append them to the 'posts' slice
	for contents.Next() {
		var post Post
		if err := contents.Scan(&post.Title, &post.Description, &post.CategoryName, &post.Nblike); err != nil {
			log.Printf("Erreur de serveur: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return
		}
		posts = append(posts, post)
	}

	// Prepare data structure for HTML template
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

	// Execute the HTML template with the fetched data
	tmpl.Execute(w, data)
}

func (u *User) processLogout(w http.ResponseWriter, r *http.Request) {
	// Parse the HTML template file
	tmpl, err := template.ParseFiles("logouttest.html")
	if err != nil {
		log.Printf("Erreur de serveur: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return
	}

	// Execute the HTML template
	tmpl.Execute(w, nil)
}

// getComments retrieves comments associated with a specific post ID from the database.
func getComments(w http.ResponseWriter, r *http.Request, postID int) []Comment {
	var comments []Comment

	// Open a connection to the SQLite database
	db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
	if dbInitErr != nil {
		http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
		return nil
	}
	defer db.Close()

	// Query the database for comments related to the given post ID
	contents, err := db.Query("SELECT comments2_text, comments2_author_id FROM comments2 WHERE comments2_post_id = ?", postID)
	if err != nil {
		log.Printf("Erreur de serveur: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return nil
	}
	defer contents.Close()

	// Iterate through the retrieved comments
	for contents.Next() {
		var comment Comment
		err := contents.Scan(&comment.Description, &comment.AuthorId)
		if err != nil {
			log.Printf("Erreur de serveur: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return nil
		}

		// Query the database to fetch the author's username based on author ID
		authorErr := db.QueryRow("SELECT username FROM users WHERE user_id=?", comment.AuthorId).Scan(&comment.AuthorName)
		if authorErr != nil {
			log.Printf("Erreur de serveur: %v", authorErr)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return nil
		}

		// Append the comment to the comments slice
		comments = append(comments, comment)
	}

	// Check for any errors during iteration
	if err := contents.Err(); err != nil {
		log.Printf("Erreur de serveur: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return nil
	}

	// Return the list of comments
	return comments
}

// getPosts retrieves posts belonging to a specific category ID from the database.
func getPosts(w http.ResponseWriter, r *http.Request, categoryID int) []Post {
	var posts []Post

	// Open a connection to the SQLite database
	db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
	if dbInitErr != nil {
		http.Error(w, "Erreur de base de données", http.StatusInternalServerError)
		return nil
	}
	defer db.Close()

	// Query the database for posts related to the given category ID
	contents, err := db.Query("SELECT posts_description, posts_title, posts_profile_picture, posts_id, category_name FROM posts WHERE category_id = ?", categoryID)
	if err != nil {
		log.Printf("Erreur de serveur: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return nil
	}
	defer contents.Close()

	// Iterate through the retrieved posts
	for contents.Next() {
		var post Post
		err := contents.Scan(&post.Description, &post.Title, &post.Base64Image, &post.ID, &post.CategoryName)
		if err != nil {
			log.Printf("Erreur de serveur: %v", err)
			http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
			return nil
		}

		// Append the post to the posts slice
		posts = append(posts, post)
	}

	// Check for any errors during iteration
	if err := contents.Err(); err != nil {
		log.Printf("Erreur de serveur: %v", err)
		http.Error(w, "Erreur de serveur", http.StatusInternalServerError)
		return nil
	}

	// Return the list of posts
	return posts
}

// Feed handles the logic for displaying posts and categories in the feed.
func (u *User) Feed(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "userSession")
	if err != nil {
		log.Printf("Error retrieving session: %v", err)
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	userID, ok := session.Values["userID"].(int)
	if !ok {
		log.Println("Error: userID not found in session")
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	var posts []Post
	var categories []Category

	// Open a connection to the SQLite database
	db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
	if dbInitErr != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Define the variable to hold query results
	var contents *sql.Rows

	// Determine the filterOrder and execute the appropriate query
	switch filterOrder {
	case "recent":
		request, err := db.Query("SELECT posts_id, posts_profile_picture, posts_title, posts_description, category_name, posts_nblike, posts_nbdislike FROM posts")
		if err != nil {
			log.Printf("Server error: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		contents = request

	case "oldest":
		request, err := db.Query("SELECT posts_id, posts_profile_picture, posts_title, posts_description, category_name, posts_nblike, posts_nbdislike FROM posts ORDER BY posts_id DESC")
		if err != nil {
			log.Printf("Server error: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		contents = request

	case "most-likes":
		request, err := db.Query("SELECT posts_id, posts_profile_picture, posts_title, posts_description, category_name, posts_nblike, posts_nbdislike FROM posts ORDER BY posts_nblike DESC")
		if err != nil {
			log.Printf("Server error: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		contents = request

	case "least-likes":
		request, err := db.Query("SELECT posts_id, posts_profile_picture, posts_title, posts_description, category_name, posts_nblike, posts_nbdislike FROM posts ORDER BY posts_nblike ASC")
		if err != nil {
			log.Printf("Server error: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		contents = request

	case "most-interactions":
		request, err := db.Query("SELECT posts_id, posts_profile_picture, posts_title, posts_description, category_name, posts_nblike, posts_nbdislike FROM posts ORDER BY posts_nbcomment DESC")
		if err != nil {
			log.Printf("Server error: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		contents = request

	case "least-interactions":
		request, err := db.Query("SELECT posts_id, posts_profile_picture, posts_title, posts_description, category_name, posts_nblike, posts_nbdislike FROM posts ORDER BY posts_nbcomment ASC")
		if err != nil {
			log.Printf("Server error: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		contents = request

	case "you liked":
		request, err := db.Query("SELECT posts_id, posts_profile_picture, posts_title, posts_description, category_name, posts_nblike, posts_nbdislike FROM posts JOIN postslikes ON posts.posts_id = postslikes.post_id WHERE postslikes.user_id = ?", userID)
		if err != nil {
			log.Printf("Server error: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		contents = request

	default:
		request, err := db.Query("SELECT posts_id, posts_profile_picture, posts_title, posts_description, category_name, posts_nblike, posts_nbdislike FROM posts")
		if err != nil {
			log.Printf("Server error: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		contents = request
	}

	defer contents.Close()

	// Iterate through the retrieved posts and check user interactions
	for contents.Next() {
		var post Post
		if err := contents.Scan(&post.ID, &post.Base64Image, &post.Title, &post.Description, &post.CategoryName, &post.Nblike, &post.Nbdislike); err != nil {
			log.Printf("Server error: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}

		// Check if the user has liked or disliked this post
		var exists bool
		query := "SELECT EXISTS(SELECT 1 FROM postslikes WHERE post_id = ? AND user_id = ?)"
		err = db.QueryRow(query, post.ID, userID).Scan(&exists)
		if err != nil {
			log.Printf("Server error: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		post.Liked = exists

		query = "SELECT EXISTS(SELECT 1 FROM postsdislikes WHERE post_id = ? AND user_id = ?)"
		err = db.QueryRow(query, post.ID, userID).Scan(&exists)
		if err != nil {
			log.Printf("Server error: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		post.Disliked = exists

		// Append the processed post to the posts slice
		posts = append(posts, post)
	}

	if err := contents.Err(); err != nil {
		log.Printf("Server error: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Retrieve categories for display in the feed
	request, err := db.Query("SELECT category_id, category_profile_picture, category_name, category_nbpost FROM categories")
	if err != nil {
		log.Printf("Server error: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer request.Close()

	// Iterate through categories and append to the categories slice
	for request.Next() {
		var category Category
		if err := request.Scan(&category.ID, &category.Base64Image, &category.Title, &category.NbPost); err != nil {
			log.Printf("Server error: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		categories = append(categories, category)
	}

	if err := request.Err(); err != nil {
		log.Printf("Server error: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Prepare data to be rendered in the template
	data := struct {
		Posts      []Post
		Categories []Category
	}{
		Posts:      posts,
		Categories: categories,
	}

	// Parse and execute the template to render the feed page
	tmpl, err := template.ParseFiles("post.html")
	if err != nil {
		log.Printf("Server error: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, data)
}

// Feed2 handles the logic for displaying categories and liked categories.
func (u *User) Feed2(w http.ResponseWriter, r *http.Request) {
	var categories []Category      // Slice to hold all categories
	var categoriesLiked []Category // Slice to hold categories liked by the user

	// Open a connection to the SQLite database
	db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
	if dbInitErr != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	var contents *sql.Rows // Variable to hold query results

	// Determine the filterOrder and execute the appropriate query
	if filterOrder == "recent" {
		request, err := db.Query("SELECT category_id, category_profile_picture, category_name, category_description FROM categories")
		if err != nil {
			log.Printf("Server error: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		contents = request

	} else if filterOrder == "oldest" {
		request, err := db.Query("SELECT category_id, category_profile_picture, category_name, category_description FROM categories ORDER BY category_id DESC")
		if err != nil {
			log.Printf("Server error: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		contents = request

	} else if filterOrder == "most-likes" {
		request, err := db.Query("SELECT category_id, category_profile_picture, category_name, category_description FROM categories ORDER BY category_nblike DESC")
		if err != nil {
			log.Printf("Server error: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		contents = request

	} else if filterOrder == "least-likes" {
		request, err := db.Query("SELECT category_id, category_profile_picture, category_name, category_description FROM categories ORDER BY category_nblike ASC")
		if err != nil {
			log.Printf("Server error: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		contents = request

	} else if filterOrder == "most-interactions" {
		request, err := db.Query("SELECT category_id, category_profile_picture, category_name, category_description FROM categories ORDER BY category_nbpost DESC")
		if err != nil {
			log.Printf("Server error: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		contents = request

	} else if filterOrder == "least-interactions" {
		request, err := db.Query("SELECT category_id, category_profile_picture, category_name, category_description FROM categories ORDER BY category_nbcomment ASC")
		if err != nil {
			log.Printf("Server error: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		contents = request

	} else {
		request, err := db.Query("SELECT category_id, category_profile_picture, category_name, category_description FROM categories")
		if err != nil {
			log.Printf("Server error: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		contents = request
	}

	defer contents.Close()

	// Iterate through the retrieved categories and populate the categories slice
	for contents.Next() {
		var category Category
		if err := contents.Scan(&category.ID, &category.Base64Image, &category.Title, &category.Description); err != nil {
			log.Printf("Server error: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		categories = append(categories, category)
	}

	if err := contents.Err(); err != nil {
		log.Printf("Server error: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Query to retrieve categories liked by the user (Currently commented out)
	// var categoriesLiked []Category
	// request, err := db.Query("SELECT category_id, category_profile_picture, category_name, category_nbpost FROM categories")

	request, err := db.Query("SELECT category_id, category_profile_picture, category_name, category_nbpost FROM categories")
	if err != nil {
		log.Printf("Server error: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer request.Close()

	// Iterate through categories liked by the user and populate categoriesLiked slice
	for request.Next() {
		var categoryLiked Category
		if err := request.Scan(&categoryLiked.ID, &categoryLiked.Base64Image, &categoryLiked.Title, &categoryLiked.NbPost); err != nil {
			log.Printf("Server error: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		categoriesLiked = append(categoriesLiked, categoryLiked)
	}

	if err := request.Err(); err != nil {
		log.Printf("Server error: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Prepare data to be rendered in the template
	data := struct {
		CategoriesLiked []Category
		Categories      []Category
	}{
		CategoriesLiked: categoriesLiked,
		Categories:      categories,
	}

	// Parse and execute the template to render the category page
	tmpl, err := template.ParseFiles("category.html")
	if err != nil {
		log.Printf("Server error: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, data)
}

// createCategory handles the creation of a new category.
func (u *User) createCategory(w http.ResponseWriter, r *http.Request) {
	// Retrieve user session
	session, err := store.Get(r, "userSession")
	if err != nil {
		log.Printf("Error retrieving session: %v", err)
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	// Check if userID exists in session
	_, ok := session.Values["userID"].(int)
	if !ok {
		http.Error(w, "You are not connected", http.StatusInternalServerError)
		return
	}

	// Open connection to SQLite database
	db, dbInitErr := sql.Open("sqlite3", "./forumv3.db")
	if dbInitErr != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Parse multipart form with max file size of 20MB
	err = r.ParseMultipartForm(20 << 20)
	if err != nil {
		log.Printf("Error parsing form: %v", err)
		http.Error(w, "Error parsing form", http.StatusInternalServerError)
		return
	}

	// Retrieve form values
	message := r.FormValue("category-description")
	title := r.FormValue("category-title")
	file, _, err := r.FormFile("category-attachment")
	if err != nil {
		http.Error(w, "Error getting file", http.StatusBadRequest)
		return
	}

	// Read file into bytes buffer
	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, file); err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}
	fileBytes := buf.Bytes()

	// Prepare SQL statement for category insertion
	stmt, err := db.Prepare("INSERT INTO categories(category_name, category_description, category_profile_picture) VALUES(?, ?, ?)")
	if err != nil {
		http.Error(w, "Error preparing SQL statement", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	// Encode file bytes to base64 string
	imageString := base64.StdEncoding.EncodeToString(fileBytes)

	// Execute SQL statement to insert new category
	_, err = stmt.Exec(title, message, imageString)
	if err != nil {
		http.Error(w, "Error executing SQL statement", http.StatusInternalServerError)
		return
	}

	// Redirect user after category creation
	http.Redirect(w, r, "http://localhost:5500/", http.StatusSeeOther)
}

func main() {
	// Serve static files from the "public" directory
	fs := http.FileServer(http.Dir("public"))
	http.Handle("/public/", http.StripPrefix("/public/", fs))

	// Initialize User handler for various routes
	http.Handle("/", new(User))
	http.Handle("/signin", new(User))
	http.Handle("/profile", new(User))
	http.Handle("/login", new(User))
	http.Handle("/logout", new(User))
	http.Handle("/posts", new(User))
	http.Handle("/post", new(User))
	http.Handle("/user-profile", new(User))

	// Define handlers for specific HTTP routes
	http.HandleFunc("/submit-report", submitReportHandler)
	http.HandleFunc("/view-reports", viewReportsHandler)
	http.HandleFunc("/delete-post", deletePostHandler)
	http.HandleFunc("/ignore-report", ignoreReportHandler)

	// Start the HTTP server on port 5500
	log.Fatal(http.ListenAndServe(":5500", nil))
}

// getUserIdFromRequest retrieves the user ID from the request cookie.
func getUserIdFromRequest(r *http.Request) (int, error) {
	// Retrieve the "user_id" cookie from the request
	cookie, err := r.Cookie("user_id")
	if err != nil {
		return 0, err
	}
	// Convert the cookie value (string) to an integer (user ID)
	id, err := strconv.Atoi(cookie.Value)
	if err != nil {
		return 0, err
	}
	// Return the user ID
	return id, nil
}

// submitReportHandler handles the submission of a report for a post.
func submitReportHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure the request method is POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var postID int
	var err error

	// Check if post-id is available (version with hidden field in uniquePost.html)
	if postIDStr := r.FormValue("post-id"); postIDStr != "" {
		postID, err = strconv.Atoi(postIDStr)
		if err != nil {
			http.Error(w, "Invalid post ID", http.StatusBadRequest)
			return
		}
	} else {
		// Otherwise, extract post ID from post-url (version with post-url field in index.html)
		postURL := r.FormValue("post-url")
		postID, err = extractPostIDFromURL(postURL)
		if err != nil {
			http.Error(w, "Invalid post ID", http.StatusBadRequest)
			return
		}
	}

	reason := r.FormValue("report-reason")
	comment := r.FormValue("report-comment")

	// Create a Report object with gathered data
	report := Report{
		PostID:  postID,
		Reason:  reason,
		Comment: comment,
		Status:  "active",
	}

	// Example report management (adapt according to your application)
	reportsLock.Lock()
	reports = append(reports, report)
	reportsLock.Unlock()

	// Redirect user to homepage after report submission
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// extractPostIDFromURL extracts the post ID from a given post URL.
func extractPostIDFromURL(postURL string) (int, error) {
	// Parse the post URL
	u, err := url.Parse(postURL)
	if err != nil {
		return 0, err
	}

	// Get the value of the query parameter "id"
	idStr := u.Query().Get("id")
	// Convert the ID string to an integer
	postID, err := strconv.Atoi(idStr)
	if err != nil {
		return 0, err
	}

	// Return the extracted post ID
	return postID, nil
}

// viewReportsHandler handles the viewing of reports by administrators.
func viewReportsHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve the user ID from the request cookie
	idUSER, err := getUserIdFromRequest(r)
	if err != nil {
		http.Error(w, "Error: User not logged in", http.StatusUnauthorized)
		return
	}

	// Load user information from the database
	var currentUser User
	err = currentUser.loadUserFromDB(idUSER)
	if err != nil {
		log.Printf("Error loading user information: %v", err)
		http.Error(w, "Error retrieving user information", http.StatusInternalServerError)
		return
	}

	// Redirect if the current user is not an admin
	if currentUser.Role != "admin" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Parse the template file
	tmpl, err := template.ParseFiles("viewReports.html")
	if err != nil {
		log.Printf("Error parsing template: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Lock the reports slice for reading
	reportsLock.Lock()
	defer reportsLock.Unlock()

	// Prepare data to pass into the template
	type TemplateData struct {
		Username string
		Role     string
		Reports  []Report // Ensure to pass your reports here
	}

	data := TemplateData{
		Username: currentUser.Username,
		Role:     currentUser.Role,
		Reports:  reports, // Replace with your slice of reports
	}

	// Execute the template with the provided data
	err = tmpl.Execute(w, data)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
}

// deletePostHandler handles the deletion of a post.
func deletePostHandler(w http.ResponseWriter, r *http.Request) {
	// Check if the request method is POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract the post ID from the form data
	postID, err := strconv.Atoi(r.FormValue("post-id"))
	if err != nil {
		http.Error(w, "Invalid post ID", http.StatusBadRequest)
		return
	}

	// Print a message indicating the post ID being deleted
	fmt.Printf("Deleting post with ID: %d\n", postID)

	// Open the database connection
	db, err := sql.Open("sqlite3", "./forumv3.db")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Delete the post from the database
	_, err = db.Exec("DELETE FROM posts WHERE posts_id = ?", postID)
	if err != nil {
		log.Printf("Error deleting post: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Remove associated reports from the in-memory reports slice
	reportsLock.Lock()
	for i, report := range reports {
		if report.PostID == postID {
			reports = append(reports[:i], reports[i+1:]...)
			break
		}
	}
	reportsLock.Unlock()

	// Redirect to the view-reports page after successful deletion
	http.Redirect(w, r, "/view-reports", http.StatusSeeOther)
}

// ignoreReportHandler handles the ignoring of a report for a post.
func ignoreReportHandler(w http.ResponseWriter, r *http.Request) {
	// Check if the request method is POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract the post ID from the form data
	postID, err := strconv.Atoi(r.FormValue("post-id"))
	if err != nil {
		http.Error(w, "Invalid post ID", http.StatusBadRequest)
		return
	}

	// Print a message indicating the post ID for which report is being ignored
	fmt.Printf("Ignoring report for post with ID: %d\n", postID)

	// Lock the reports slice for reading and updating
	reportsLock.Lock()
	defer reportsLock.Unlock()

	// Update the status of the report to "ignored"
	for i, report := range reports {
		if report.PostID == postID {
			reports[i].Status = "ignored"
			break
		}
	}

	// Redirect to the view-reports page after ignoring the report
	http.Redirect(w, r, "/view-reports", http.StatusSeeOther)
}
