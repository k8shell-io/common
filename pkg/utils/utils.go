package utils

import (
	"encoding/base64"
	"fmt"
	"math"
	"strings"

	"github.com/k8shell-io/common/pkg/logger"
)

var log = logger.NewLogger("system-utils")

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

// ClampUint32ToUint16 safely converts uint32 to uint16, clamping to 65535 if overflow.
func ClampUint32ToUint16(v uint32) uint16 {
	if v > 65535 {
		log.Warn().Msgf("ClampUint32ToUint16: clamped value %d to 65535", v)
		return 65535
	}
	return uint16(v)
}

// SafeIntToUint16 safely converts int to uint16, clamping to 0-65535.
func SafeIntToUint16(v int) uint16 {
	if v < 0 {
		log.Warn().Msgf("SafeIntToUint16: clamped negative value %d to 0", v)
		return 0
	}
	if v > 65535 {
		log.Warn().Msgf("SafeIntToUint16: clamped value %d to 65535", v)
		return 65535
	}
	return uint16(v)
}

// SafeIntToUint64 converts int to uint64, assuming non-negative input (e.g., from Read()).
func SafeIntToUint64(v int) uint64 {
	if v < 0 {
		log.Warn().Msgf("SafeIntToUint64: clamped negative value %d to 0", v)
		return 0
	}
	return uint64(v)
}

// SafeIntToUint32 converts int to uint32, clamping negative values to 0.
func SafeIntToUint32(v int) uint32 {
	if v < 0 {
		log.Warn().Msgf("SafeIntToUint32: clamped negative value %d to 0", v)
		return 0
	}
	if v > 2147483647 {
		log.Warn().Msgf("SafeIntToUint32: clamped value %d to 2147483647", v)
		return 2147483647
	}
	return uint32(v)
}

// SafeIntToInt32 converts int to int32, clamping to int32 max/min.
func SafeIntToInt32(v int) int32 {
	if v > 2147483647 {
		log.Warn().Msgf("SafeIntToInt32: clamped value %d to 2147483647", v)
		return 2147483647
	}
	if v < -2147483648 {
		log.Warn().Msgf("SafeIntToInt32: clamped value %d to -2147483648", v)
		return -2147483648
	}
	return int32(v)
}

// Safeu32ToInt converts uint32 to int, returning 0 if overflow would occur.
func Safeu32ToInt(v uint32) int {
	if uint64(v) > uint64(math.MaxInt) {
		return 0
	}
	return int(v)
}
