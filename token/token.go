package token

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// If the timestamp for token issue is not within the last hour, APNs rejects subsequent push messages
const ttl = 40 * 60

var (
	ErrInvalidKID     = TokenError{"Invalid key identifier"}
	ErrInvalidISS     = TokenError{"Invalid Team ID"}
	ErrInvalidPEM     = TokenError{"Invalid PEM file"}
	ErrInvalidPEMType = TokenError{"Invalid PEM type"}
	ErrMissingPEM     = TokenError{"PEM signature is missing"}
)

type TokenError struct {
	Reason string
}

func (err TokenError) Error() string { return err.Reason }

type Token struct {
	sync.Mutex

	TeamID   string
	KeyID    string
	IssuedAt int64

	SigningKey *ecdsa.PrivateKey
	JWT        string
}

func NewToken(privateKeyFilename, teamID, keyID string) (*Token, error) {
	// read private key file
	rawKey, err := ioutil.ReadFile(privateKeyFilename)
	if err != nil {
		return nil, err
	}

	// parse key
	privateKey, err := parseECDSAKey(rawKey)
	if err != nil {
		return nil, err
	}

	return &Token{
		SigningKey: privateKey,
		TeamID:     teamID,
		KeyID:      keyID,
	}, nil
}

// Checks expiration
func (token *Token) Expired() bool {
	return time.Now().Unix() >= (token.IssuedAt + ttl)
}

// Updates IssuedAt value and prepares JWT string
func (token *Token) SignJWT() error {
	err := token.validate()
	if err != nil {
		return err
	}

	token.IssuedAt = time.Now().Unix()
	jwtToken := &jwt.Token{
		Method: jwt.SigningMethodES256,
		Header: map[string]interface{}{
			"kid": token.KeyID,
			"alg": "ES256",
		},
		Claims: jwt.MapClaims{
			"iss": token.TeamID,
			"iat": token.IssuedAt,
		},
	}
	token.JWT, err = jwtToken.SignedString(token.SigningKey)
	if err != nil {
		return err
	}

	return nil
}

// Refresh JWT value if token is expired
func (token *Token) RefreshJWT() bool {
	token.Lock()
	defer token.Unlock()
	if token.Expired() {
		token.SignJWT()
		return true
	}

	return false
}

// Checks jwt-required fields
func (token *Token) validate() error {
	if len(token.KeyID) != 10 {
		return ErrInvalidKID
	} else if len(token.TeamID) != 10 {
		return ErrInvalidISS
	} else if token.SigningKey == nil {
		return ErrMissingPEM
	}

	return nil
}

func parseECDSAKey(rawKey []byte) (*ecdsa.PrivateKey, error) {
	// decode
	block, _ := pem.Decode(rawKey)
	if block == nil {
		return nil, ErrInvalidPEM
	}

	// parse block into a key
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// validate key type
	switch pk := key.(type) {
	case *ecdsa.PrivateKey:
		return pk, nil
	default:
		return nil, ErrInvalidPEMType
	}
}
