package utils

import (
	"encoding/json"
	"net/http"
)

type ProblemJSONResponse struct {
	Type     string `json:"type"`
	Status   int    `json:"status"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Instance string `json:"instance"`
}

type ErrorResponse struct {
	Types []string `json:"types"`
}

func BasicJsonResponse(w http.ResponseWriter, response interface{}, statusCode int) {
	w.WriteHeader(statusCode)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
