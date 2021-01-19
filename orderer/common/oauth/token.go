package oauth

import (
	"crypto/x509"
	"time"

	"gopkg.in/square/go-jose.v2/jwt"
)

// Token represents the credentials used to authorize
// the requests to access protected resources on the OAuth 2.0
// provider's backend.
type Token struct {
	Info TokenInfo

	// CreatedAt is the time the access token was created at. Expiration of the
	// access token is determined based on whether the ExpiresIn duration has passed
	// since CreateAt.
	CreateAt time.Time

	Certificates [][]*x509.Certificate

	Claims jwt.Claims
}

// TokenInfo holds the token info for the requested access token to be marshalled
// in the JSON response.
type TokenInfo struct {
	// AccessToken is the token that authorizes and authenticates
	// the requests.
	AccessToken string `json:"access_token"`

	// TokenType is the type of token. Can be "Bearer", "MAC", or "Basic".
	TokenType string `json:"token_type,omitempty"`

	// ExpiresIn is the lifetime in seconds of the access token.
	// For example, the value "3600" denotes that the access token will
	// expire in one hour from the time the response was generated.
	ExpiresIn int64 `json:"expires_in,omitempty"`
}
