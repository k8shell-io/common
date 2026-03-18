// Copyright 2026 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/k8shell-io/common/pkg/models"
)

// Sentinel errors returned by JWTVerifier.VerifyToken.
// Use errors.Is to distinguish failure reasons.
var (
	// ErrTokenExpired is returned when the token's expiry time has passed.
	ErrTokenExpired = errors.New("jwt: token has expired")

	// ErrTokenInvalidSignature is returned when the token signature does not
	// match the expected signing key.
	ErrTokenInvalidSignature = errors.New("jwt: token signature is invalid")

	// ErrTokenMalformed is returned when the token string is not a valid JWT.
	ErrTokenMalformed = errors.New("jwt: token is malformed")
)

// JWTIssuerConfig contains configuration for JWT token issuance.
type JWTIssuerConfig struct {
	// Enabled toggles JWT issuance. When false, the issuer is not initialized.
	Enabled bool `yaml:"enabled"`

	// Issuer is the value placed in the "iss" claim.
	Issuer string `yaml:"issuer"`

	// Audience is the value placed in the "aud" claim.
	Audience string `yaml:"audience"`

	// Expiry is the token lifetime (e.g. "1h", "8h", "24h").
	// Defaults to 1 hour when unset.
	Expiry time.Duration `yaml:"expiry"`

	// SigningMethod selects the signing algorithm. Supported values:
	//   hs256 (default) – HMAC-SHA-256, requires SecretKey
	//   rs256            – RSA-SHA-256,  requires PrivateKeyFile
	//   es256            – ECDSA-P256,   requires PrivateKeyFile
	SigningMethod string `yaml:"signingMethod"`

	// SecretKey is the HMAC signing secret (used with hs256).
	SecretKey string `yaml:"secretKey"`

	// PrivateKeyFile is the path to a PEM-encoded RSA or ECDSA private key
	// (used with rs256 / es256).
	PrivateKeyFile string `yaml:"privateKeyFile"`
}

// JWTVerifierConfig contains configuration for JWT token verification.
type JWTVerifierConfig struct {
	// Issuer is the expected "iss" claim value. When set, tokens with a
	// different issuer are rejected.
	Issuer string `yaml:"issuer"`

	// Audience is the expected "aud" claim value. When set, tokens without
	// this audience are rejected.
	Audience string `yaml:"audience"`

	// SigningMethod must match the algorithm used to sign the tokens.
	// Supported values: hs256 (default), rs256, es256.
	SigningMethod string `yaml:"signingMethod"`

	// SecretKey is the HMAC verification secret (used with hs256).
	SecretKey string `yaml:"secretKey"`

	// PublicKeyFile is the path to a PEM-encoded RSA or ECDSA public key
	// (used with rs256 / es256). Takes precedence over PrivateKeyFile.
	PublicKeyFile string `yaml:"publicKeyFile"`
}

// UserClaims are the JWT claims embedded in tokens issued for a user.
// Standard registered claims are promoted from jwt.RegisteredClaims; the
// remaining fields carry k8Shell-specific user attributes.
type UserClaims struct {
	jwt.RegisteredClaims

	// Email is the user's email address.
	Email string `json:"email,omitempty"`

	// Name is the user's full name.
	Name string `json:"name,omitempty"`

	// UID is the POSIX user-id of the user.
	UID uint32 `json:"uid"`

	// GID is the POSIX primary group-id of the user.
	GID uint32 `json:"gid"`

	// Roles lists the roles granted to the user.
	Roles []string `json:"roles,omitempty"`

	// Organization is the user's organisation.
	Organization string `json:"org,omitempty"`

	// Source identifies the identity provider that owns this user record.
	Source string `json:"source,omitempty"`
}

// JWTIssuer creates and signs JWT tokens for authenticated users.
type JWTIssuer struct {
	cfg           JWTIssuerConfig
	signingMethod jwt.SigningMethod
	signingKey    interface{}
}

// NewJWTIssuer constructs a JWTIssuer from the provided configuration.
// Returns an error when the configuration is invalid or keying material
// cannot be loaded.
func NewJWTIssuer(cfg JWTIssuerConfig) (*JWTIssuer, error) {
	issuer := &JWTIssuer{cfg: cfg}

	if cfg.Expiry == 0 {
		issuer.cfg.Expiry = time.Hour
	}

	method := cfg.SigningMethod
	if method == "" {
		method = "hs256"
	}

	switch method {
	case "hs256":
		if cfg.SecretKey == "" {
			return nil, fmt.Errorf("jwt: secretKey is required for hs256")
		}
		issuer.signingMethod = jwt.SigningMethodHS256
		issuer.signingKey = []byte(cfg.SecretKey)

	case "rs256":
		key, err := loadRSAPrivateKey(cfg.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("jwt: load RSA private key: %w", err)
		}
		issuer.signingMethod = jwt.SigningMethodRS256
		issuer.signingKey = key

	case "es256":
		key, err := loadECPrivateKey(cfg.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("jwt: load EC private key: %w", err)
		}
		issuer.signingMethod = jwt.SigningMethodES256
		issuer.signingKey = key

	default:
		return nil, fmt.Errorf("jwt: unsupported signing method %q (use hs256, rs256 or es256)", method)
	}

	return issuer, nil
}

// newJTI generates a random UUID v4 string for use as the JWT ID claim.
func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// IssueToken creates a signed JWT string for the given user. The token
// includes both standard registered claims and k8Shell-specific user
// attributes as additional claims.
// It returns the JTI (JWT ID), the signed token string, and any error.
func (j *JWTIssuer) IssueToken(user *models.User) (jti string, signed string, err error) {
	now := time.Now()

	jti, err = newJTI()
	if err != nil {
		return "", "", fmt.Errorf("jwt: generate jti: %w", err)
	}

	claims := UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Subject:   user.Username,
			Issuer:    j.cfg.Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(j.cfg.Expiry)),
		},
		Email:        user.Email,
		Name:         user.Fullname,
		UID:          user.UID,
		GID:          user.GID,
		Roles:        user.Roles,
		Organization: user.Organization,
		Source:       user.Source,
	}

	if j.cfg.Audience != "" {
		claims.Audience = jwt.ClaimStrings{j.cfg.Audience}
	}

	token := jwt.NewWithClaims(j.signingMethod, claims)

	signed, err = token.SignedString(j.signingKey)
	if err != nil {
		return "", "", fmt.Errorf("jwt: sign token: %w", err)
	}

	return jti, signed, nil
}

// loadRSAPrivateKey reads and parses a PEM-encoded RSA private key from path.
func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return jwt.ParseRSAPrivateKeyFromPEM(data)
}

// loadECPrivateKey reads and parses a PEM-encoded ECDSA private key from path.
func loadECPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return jwt.ParseECPrivateKeyFromPEM(data)
}

// loadRSAPublicKey reads and parses a PEM-encoded RSA public key from path.
func loadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return jwt.ParseRSAPublicKeyFromPEM(data)
}

// loadECPublicKey reads and parses a PEM-encoded ECDSA public key from path.
func loadECPublicKey(path string) (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return jwt.ParseECPublicKeyFromPEM(data)
}

// JWTVerifier validates JWT tokens, checking both signature integrity and
// expiration. It can be used independently from JWTIssuer.
type JWTVerifier struct {
	// cfg holds the original configuration for issuer/audience validation.
	cfg JWTVerifierConfig

	// verificationKey is the key used to verify the token signature.
	// For hs256 it is []byte; for rs256 *rsa.PublicKey; for es256 *ecdsa.PublicKey.
	verificationKey interface{}

	// parser is a pre-configured jwt.Parser with the expected issuer and audience.
	parser *jwt.Parser
}

// NewJWTVerifier constructs a JWTVerifier from the provided configuration.
//
// For hs256 SecretKey is used for verification.
// For rs256 / es256 the verification key is resolved in this order:
//  1. PublicKeyFile (if set)
//  2. Public key extracted from PrivateKeyFile
func NewJWTVerifier(cfg JWTVerifierConfig) (*JWTVerifier, error) {
	v := &JWTVerifier{cfg: cfg}

	method := cfg.SigningMethod
	if method == "" {
		method = "hs256"
	}

	switch method {
	case "hs256":
		if cfg.SecretKey == "" {
			return nil, fmt.Errorf("jwt: secretKey is required for hs256")
		}
		v.verificationKey = []byte(cfg.SecretKey)

	case "rs256":
		if cfg.PublicKeyFile != "" {
			pub, err := loadRSAPublicKey(cfg.PublicKeyFile)
			if err != nil {
				return nil, fmt.Errorf("jwt: load RSA public key: %w", err)
			}
			v.verificationKey = pub
		} else {
			return nil, fmt.Errorf("jwt: rs256 requires publicKeyFile")
		}

	case "es256":
		if cfg.PublicKeyFile != "" {
			pub, err := loadECPublicKey(cfg.PublicKeyFile)
			if err != nil {
				return nil, fmt.Errorf("jwt: load EC public key: %w", err)
			}
			v.verificationKey = pub
		} else {
			return nil, fmt.Errorf("jwt: es256 requires publicKeyFile")
		}

	default:
		return nil, fmt.Errorf("jwt: unsupported signing method %q (use hs256, rs256 or es256)", method)
	}

	parserOpts := []jwt.ParserOption{
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	}
	if cfg.Issuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(cfg.Issuer))
	}
	if cfg.Audience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(cfg.Audience))
	}
	v.parser = jwt.NewParser(parserOpts...)

	return v, nil
}

// VerifyToken parses and validates tokenStr. It returns the embedded
// UserClaims on success, or one of the sentinel errors on failure:
//
//   - ErrTokenExpired          – token exists but has expired
//   - ErrTokenInvalidSignature – signature does not match the key
//   - ErrTokenMalformed        – string is not a valid JWT
//   - any other error          – audience/issuer mismatch or internal failure
func (v *JWTVerifier) VerifyToken(tokenStr string) (*UserClaims, error) {
	var claims UserClaims

	_, err := v.parser.ParseWithClaims(tokenStr, &claims, func(t *jwt.Token) (interface{}, error) {
		return v.verificationKey, nil
	})
	if err == nil {
		return &claims, nil
	}

	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return nil, ErrTokenExpired
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return nil, ErrTokenInvalidSignature
	case errors.Is(err, jwt.ErrTokenMalformed):
		return nil, ErrTokenMalformed
	default:
		return nil, fmt.Errorf("jwt: verify token: %w", err)
	}
}
