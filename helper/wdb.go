package helper

import (
	"encoding/json"
	"log"
	"net/http"

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