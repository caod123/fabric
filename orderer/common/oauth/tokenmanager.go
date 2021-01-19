package oauth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"io"
	"time"

	"github.com/hyperledger/fabric/common/util"
	"github.com/hyperledger/fabric/msp"
	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const defaultExpiryInSeconds = 300

type TokenManager struct {
	observedJTIs map[string]struct{}
	tokenStore   map[string]*Token

	expiryInSeconds int64
}

func NewTokenManager(expiryInSeconds int64) *TokenManager {
	if expiryInSeconds == 0 {
		expiryInSeconds = defaultExpiryInSeconds
	}

	return &TokenManager{
		observedJTIs: make(map[string]struct{}),
		tokenStore:   make(map[string]*Token),

		expiryInSeconds: expiryInSeconds,
	}
}

func NewSigner(certs []*x509.Certificate, privKey *ecdsa.PrivateKey) (jose.Signer, error) {
	key := jose.SigningKey{Algorithm: jose.ES256, Key: privKey}

	signerOpts := jose.SignerOptions{}
	signerOpts.WithType("JWT")

	x5c := [][]byte{}
	for _, c := range certs {
		x5c = append(x5c, c.Raw)
	}
	signerOpts.ExtraHeaders[jose.HeaderKey("x5c")] = x5c

	signer, err := jose.NewSigner(key, &signerOpts)
	if err != nil {
		return nil, err
	}

	return signer, nil
}

func CreateAssertion(signer jose.Signer, iss, sub string, aud []string, iat, exp time.Time) (string, error) {
	builder := jwt.Signed(signer)

	cl := jwt.Claims{
		Issuer:   iss,
		Subject:  sub,
		ID:       util.GenerateUUID(),
		Audience: jwt.Audience(aud),
		IssuedAt: jwt.NewNumericDate(iat),
		Expiry:   jwt.NewNumericDate(exp),
	}

	return builder.Claims(cl).CompactSerialize()
}

func (tm *TokenManager) ValidateAssertion(rawJWT string, pubKey *ecdsa.PublicKey, msp msp.MSP, aud []string, opts x509.VerifyOptions) (*Token, error) {
	parsedJWT, err := jwt.ParseSigned(rawJWT)
	if err != nil {
		return nil, err
	}

	cl := jwt.Claims{}
	if err := parsedJWT.Claims(pubKey, &cl); err != nil {
		return nil, err
	}

	if cl.Issuer != cl.Subject {
		return nil, errors.Errorf("iss `%s` and sub `%s` do not match", cl.Issuer, cl.Subject)
	}

	if err := cl.Validate(jwt.Expected{
		Audience: jwt.Audience(aud),
		Time:     time.Now(),
	}); err != nil {
		return nil, err
	}

	jti := cl.ID
	if _, found := tm.observedJTIs[jti]; found {
		return nil, errors.Errorf("jti `%s` already observed, preventing replay", jti)
	}

	mspID, err := msp.GetIdentifier()
	if err != nil {
		return nil, err
	}
	if cl.Issuer != mspID {
		return nil, errors.Errorf("client_id `%s` does not match local mspID `%s`", cl.Issuer, mspID)
	}

	var certificates [][]*x509.Certificate
	for _, h := range parsedJWT.Headers {
		chains, err := h.Certificates(opts)
		if err != nil {
			return nil, err
		}
		for _, ch := range chains {
			for _, c := range ch {
				identity, err := msp.DeserializeIdentity(c.Raw)
				if err != nil {
					return nil, err
				}
				if err := msp.Validate(identity); err != nil {
					return nil, err
				}
			}
		}
		certificates = append(certificates, chains...)
	}

	// Build AccessToken
	sessionID := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, sessionID); err != nil {
		panic(err)
	}

	token := &Token{
		Info: TokenInfo{
			AccessToken: base64.StdEncoding.EncodeToString(sessionID),
			TokenType:   "Bearer",
			ExpiresIn:   tm.expiryInSeconds,
		},
		CreateAt:     time.Now(),
		Certificates: certificates,
		Claims:       cl,
	}

	// Cache jti and store token
	tm.observedJTIs[cl.ID] = struct{}{}
	tm.tokenStore[token.Info.AccessToken] = token

	// Remove jti and token after expiration
	time.AfterFunc(time.Duration(tm.expiryInSeconds)*time.Second, func() {
		delete(tm.observedJTIs, token.Claims.ID)
		delete(tm.tokenStore, token.Info.AccessToken)
	})

	return token, nil
}
