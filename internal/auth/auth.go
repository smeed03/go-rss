package auth

import (
	"net/http"
	"errors"
	"strings"
)

// GetAPIKey extracts an API Key from the HTTP request headers
// Example = Authorization: ApiKey {insert apikey here}
func GetAPIKey(headers http.Header) (string, error) {
	val := headers.Get("Authorization")
	if val == "" {
		return "", errors.New("no auth info found")
	}
	vals := strings.Split(val, " ")
	if len(vals) != 2 {
		return "", errors.New("malformed auth header")
	}
	if vals[0] != "ApiKey" {
		return "", errors.New("malformed beginning of auth header")
	}
	return vals[1], nil
}