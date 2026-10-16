package totp

import (
	"encoding/base32"
	"testing"
	"time"
)

// RFC 6238 appendix B vectors (SHA-1, key "12345678901234567890"), last 6 digits.
func TestRFC6238Vectors(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for _, v := range []struct {
		unix int64
		want string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}} {
		got, err := Code(secret, time.Unix(v.unix, 0))
		if err != nil || got != v.want {
			t.Errorf("t=%d: got %s want %s (%v)", v.unix, got, v.want, err)
		}
	}
}

func TestValidateSkew(t *testing.T) {
	s := NewSecret()
	now := time.Unix(1_800_000_000, 0)
	c, _ := Code(s, now.Add(-30*time.Second))
	if !Validate(s, c, now) {
		t.Fatal("previous step rejected")
	}
	old, _ := Code(s, now.Add(-90*time.Second))
	if Validate(s, old, now) {
		t.Fatal("code three steps old accepted")
	}
	if Validate(s, "12345", now) || Validate(s, "abcdef", now) {
		t.Fatal("malformed code accepted")
	}
}
