package utils

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// encodeState builds a base64url-encoded state string as "prefix:nonce".
func EncodeState(prefix, nonce string) string {
	raw := prefix + ":" + nonce
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodeState parses a base64url-encoded state string back to prefix and nonce.
func DecodeState(state string) (prefix string, nonce string, err error) {
	b, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return "", "", fmt.Errorf("decode state: %w", err)
	}
	parts := strings.SplitN(string(b), ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid state format")
	}
	return parts[0], parts[1], nil
}
