package server

import "net/http"

func CreateServerAndRun(port string) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

	})
}
