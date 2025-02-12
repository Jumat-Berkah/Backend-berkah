package helper

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/whatsauth/itmodel"
)

func NotFound(respw http.ResponseWriter, req *http.Request) {
	var resp itmodel.Response
	resp.Response = "Not Found"
	WriteResponse(respw, http.StatusNotFound, resp)
}

func WriteResponse(respw http.ResponseWriter, statusCode int, responseStruct interface{}) {
	respw.Header().Set("Content-Type", "application/json")
	respw.WriteHeader(statusCode)
	respw.Write([]byte(Jsonstr(responseStruct)))
}

func WriteJSON(respw http.ResponseWriter, statusCode int, content interface{}) {
	respw.Header().Set("Content-Type", "application/json")
	respw.WriteHeader(statusCode)
	respw.Write([]byte(Jsonstr(content)))
}

func Jsonstr(strc interface{}) string {
	jsonData, err := json.Marshal(strc)
	if err != nil {
		log.Fatal(err)
	}
	return string(jsonData)
}

// ExtractUserID extracts the user ID from the request
func ExtractUserID(r *http.Request) string {
    // Assuming the user ID is passed in the Authorization header as a Bearer token
    authHeader := r.Header.Get("Authorization")
    if authHeader == "" {
        return ""
    }

    // Split the header to get the token part
    parts := strings.Split(authHeader, " ")
    if len(parts) != 2 || parts[0] != "Bearer" {
        return ""
    }

    return parts[1] // Assuming the token itself is the user ID
}