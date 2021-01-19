package channelparticipation

import (
	"crypto/ecdsa"
	"crypto/x509"
	"net/http"

	"github.com/hyperledger/fabric/orderer/common/oauth"
	"github.com/pkg/errors"
)

const (
	clientCredentialsValue         = "client_credentials"
	formURLEncodedContentTypeValue = "application/x-www-form-urlencoded"
	clientAssertionTypeKey         = "client_assertion_type"
	clientAssertionKey             = "client_assertion"
	grantTypeKey                   = "grant_type"
	clientAssertionJWTBearerType   = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// Retrieve an Access Token
func (h *HTTPHandler) serveTokenRequest(resp http.ResponseWriter, req *http.Request) {
	if req.Header.Get("Content-Type") != formURLEncodedContentTypeValue {
		h.sendResponseJsonError(resp, http.StatusNotAcceptable, errors.New("only Content-Type: application/x-www-form-urlencoded is supported"))
		return
	}

	accessToken, err := h.validateTokenRequest(req)
	if err != nil {
		h.sendResponseJsonError(resp, http.StatusBadRequest, err)
		return
	}

	resp.Header().Set("Cache-Control", "no-store")
	resp.Header().Set("Pragma", "no-cache")
	h.sendResponseOK(resp, accessToken.Info)
}

func (h *HTTPHandler) validateTokenRequest(r *http.Request) (*oauth.Token, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	if r.PostForm.Get(grantTypeKey) != clientCredentialsValue {
		return nil, errors.New("grant_type must be `client_credentials`")
	}
	if r.PostForm.Get(clientAssertionTypeKey) != clientAssertionJWTBearerType {
		return nil, errors.Errorf("client_assertion_type must be %s", clientAssertionJWTBearerType)
	}

	assertion := r.PostForm.Get(clientAssertionKey)
	if len(assertion) == 0 {
		return nil, errors.New("client_assertion must be set")
	}

	aud := []string{h.listenAddress + URLBaseV1Token}
	return h.tokenManager.ValidateAssertion(assertion, &ecdsa.PublicKey{}, h.localMSP, aud, x509.VerifyOptions{})
}
