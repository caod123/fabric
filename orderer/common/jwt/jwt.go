package jwt

import (
	"crypto/ecdsa"
	"crypto/x509"
	"time"

	"github.com/hyperledger/fabric/common/util"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

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

func CreateToken(signer jose.Signer, iss, sub string, aud []string, iat, exp time.Time) (string, error) {
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

func ValidateToken(rawJWT string, pubKey *ecdsa.PublicKey, clientID string, aud []string) error {
	parsedJWT, err := jwt.ParseSigned(rawJWT)
	if err != nil {
		return err
	}

	cl := jwt.Claims{}
	if err := parsedJWT.Claims(pubKey, &cl); err != nil {
		return err
	}

	return cl.Validate(jwt.Expected{
		Issuer:   clientID,
		Subject:  clientID,
		Audience: jwt.Audience(aud),
		Time:     time.Now(),
	})
}
