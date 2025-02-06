package routes

import (
	"Backend-berkah/config"
	"Backend-berkah/controller"
	"Backend-berkah/helper"
	"log"
	"net/http"
	// Middleware untuk autentikasi dan otorisasi JWT
)

func URL(w http.ResponseWriter, r *http.Request) {
    // Log request method dan path
    log.Printf("Incoming request: %s %s", r.Method, r.URL.Path)

    // Set Access Control Headers
    if config.SetAccessControlHeaders(w, r) {
        return
    }

    // Load environment variables
    config.LoadEnv()

    // Ambil metode dan path dari request
    method := r.Method
    path := r.URL.Path

    // Routing berdasarkan method dan path
    switch {
    // User authentication routes
    case method == "POST" && path == "/register":
        controller.Register(w, r)
    case method == "POST" && path == "/login":
        controller.Login(w, r)
    case method == "POST" && path == "/logout":
        controller.Logout(w, r)


    // Google OAuth routes
    case method == "GET" && path == "/auth/google/login":
        controller.HandleAuth0Login(w, r) // Menangani login dengan Google
    case method == "GET" && path == "/auth/callback":
        controller.HandleAuth0Callback(w, r) // Menangani callback dari Google
    
    //profile update
    case method == "PUT" && path == "/updateprofile":
        controller.UpdateProfile(w, r)
        
    // Admin route untuk manage CRUD
	case method == "GET" && path == "/retreive/data/location":
		controller.GetLocation(w, r)
    case method == "POST" && path == "/createlocation":
        controller.CreateLocation(w, r)
    case method == "PUT" && path == "/updatelocation":
        controller.UpdateLocation(w, r)
    case method == "DELETE" && path == "/deletelocation":
        controller.DeleteLocation(w, r)	
    case method == "GET" && path == "/retreive/data/user":
        controller.GetUsers(w, r)
    case method == "PUT" && path == "/updateuser":
        controller.UpdateUser(w, r)
    case method == "DELETE" && path == "/deleteuser":
        controller.DeleteUser(w, r)
    //profile picture
    case method == "POST" && path == "/upload/profile-picture":
        controller.UploadProfilePicture(w, r)
    case method == "GET" && path == "/profile-picture":
        controller.ServeProfilePicture(w, r)
        
    //reset password
    case method == "POST" && path == "/reset-password":
        controller.ResetPassword(w, r)
    case method == "POST" && path == "/update-password":
        controller.UpdatePassword(w, r)
    // Default route

    default:
        helper.NotFound(w, r)

    }
}
