// Package totp implements RFC 6238 time-based one-time passwords
// (SHA-1, 6 digits, 30 s steps), compatible with common authenticator apps.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	step   = 30
	digits = 6
	// Accept the previous and next step to absorb clock drift.
	skew = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a random 160-bit secret, base32 encoded.
func NewSecret() string {
	k := make([]byte, 20)
	rand.Read(k)
	return b32.EncodeToString(k)
}

// URL is the otpauth:// URI authenticator apps import (usually as a QR code).
func URL(issuer, account, secret string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprint(digits))
	v.Set("period", fmt.Sprint(step))
	label := url.PathEscape(issuer + ":" + account)
	return "otpauth://totp/" + label + "?" + v.Encode()
}

// Code computes the code for the step containing t.
func Code(secret string, t time.Time) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("totp: bad secret: %w", err)
	}
	return code(key, uint64(t.Unix()/step)), nil
}

func code(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", digits, n%1_000_000)
}

// Validate checks code against secret at time t, within ±skew steps.
func Validate(secret, given string, t time.Time) bool {
	given = strings.ReplaceAll(strings.TrimSpace(given), " ", "")
	if len(given) != digits {
		return false
	}
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return false
	}
	now := t.Unix() / step
	ok := 0
	for d := int64(-skew); d <= skew; d++ {
		ok |= subtle.ConstantTimeCompare([]byte(code(key, uint64(now+d))), []byte(given))
	}
	return ok == 1
}
