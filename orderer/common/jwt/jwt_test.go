package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestCreateJWT(t *testing.T) {
	ca := newCACert()
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caBytes)
	require.NoError(t, err)
	cert := newCert()
	certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	require.NoError(t, err)
	cert1, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	certs := []*x509.Certificate{cert1, caCert}

	clientID := "clientid"
	iat := time.Now()
	exp := iat.Add(time.Minute)
	aud := []string{"audurl"}

	signer, err := NewSigner(certs, certPrivKey)
	require.NoError(t, err)

	token, err := CreateToken(signer, clientID, clientID, aud, iat, exp)
	require.NoError(t, err)

	parsedToken, err := jwt.ParseSigned(token)
	require.NoError(t, err)

	cl := jwt.Claims{}
	err = parsedToken.Claims(&certPrivKey.PublicKey, &cl)
	require.NoError(t, err)
	require.Equal(t, clientID, cl.Issuer)
	require.Equal(t, clientID, cl.Subject)
	require.Equal(t, jwt.Audience(aud), cl.Audience)
	require.Equal(t, jwt.NewNumericDate(iat), cl.IssuedAt)
	require.Equal(t, jwt.NewNumericDate(exp), cl.Expiry)
}

func TestValidateToken(t *testing.T) {
	ca := newCACert()
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caBytes)
	require.NoError(t, err)
	cert := newCert()
	certPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	require.NoError(t, err)
	cert1, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	certs := []*x509.Certificate{cert1, caCert}

	clientID := "clientid"
	iat := time.Now()
	exp := iat.Add(time.Minute)
	aud := []string{"audurl"}

	signer, err := NewSigner(certs, certPrivKey)
	require.NoError(t, err)

	token, err := CreateToken(signer, clientID, clientID, aud, iat, exp)
	require.NoError(t, err)

	err = ValidateToken(token, &certPrivKey.PublicKey, clientID, aud)
	require.NoError(t, err)
}

func TestValidateToken_Failures(t *testing.T) {
	privKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	privKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name         string
		signingKey   *ecdsa.PrivateKey
		verifyingKey *ecdsa.PublicKey
		iss          string
		sub          string
		aud          []string
		iat          time.Time
		exp          time.Time
		expectedErr  string
	}{
		{
			name:         "invalid signature",
			signingKey:   privKey1,
			verifyingKey: &privKey2.PublicKey,
			iss:          "clientid",
			sub:          "clientid",
			aud:          []string{"audurl"},
			iat:          time.Now(),
			exp:          time.Now().Add(time.Minute),
			expectedErr:  "square/go-jose: error in cryptographic primitive",
		},
		{
			name:         "wrong iss",
			signingKey:   privKey1,
			verifyingKey: &privKey1.PublicKey,
			iss:          "bad",
			sub:          "clientid",
			aud:          []string{"audurl"},
			iat:          time.Now(),
			exp:          time.Now().Add(time.Minute),
			expectedErr:  "square/go-jose/jwt: validation failed, invalid issuer claim (iss)",
		},
		{
			name:         "wrong sub",
			signingKey:   privKey1,
			verifyingKey: &privKey1.PublicKey,
			iss:          "clientid",
			sub:          "bad",
			aud:          []string{"audurl"},
			iat:          time.Now(),
			exp:          time.Now().Add(time.Minute),
			expectedErr:  "square/go-jose/jwt: validation failed, invalid subject claim (sub)",
		},
		{
			name:         "wrong aud",
			signingKey:   privKey1,
			verifyingKey: &privKey1.PublicKey,
			iss:          "clientid",
			sub:          "clientid",
			aud:          []string{"bad"},
			iat:          time.Now(),
			exp:          time.Now().Add(time.Minute),
			expectedErr:  "square/go-jose/jwt: validation failed, invalid audience claim (aud)",
		},
		{
			name:         "expired",
			signingKey:   privKey1,
			verifyingKey: &privKey1.PublicKey,
			iss:          "clientid",
			sub:          "clientid",
			aud:          []string{"audurl"},
			iat:          time.Unix(0, 0),
			exp:          time.Unix(0, 0).Add(time.Minute),
			expectedErr:  "square/go-jose/jwt: validation failed, token is expired (exp)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs := []*x509.Certificate{}

			clientID := "clientid"
			aud := []string{"audurl"}

			signer, err := NewSigner(certs, tt.signingKey)
			token, err := CreateToken(signer, tt.iss, tt.sub, tt.aud, tt.iat, tt.exp)
			require.NoError(t, err)

			err = ValidateToken(token, tt.verifyingKey, clientID, aud)
			require.EqualError(t, err, tt.expectedErr)

		})
	}
}

func newCACert() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(2021),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
}

func newCert() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
}
