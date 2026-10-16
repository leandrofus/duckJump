// Package vault encrypts stored credentials with AES-256-GCM under a master
// key that lives outside the database (PALTA_MASTER_KEY).
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

type Vault struct {
	aead cipher.AEAD
}

func GenerateKey() string {
	k := make([]byte, 32)
	rand.Read(k)
	return base64.StdEncoding.EncodeToString(k)
}

func New(b64Key string) (*Vault, error) {
	key, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, fmt.Errorf("vault: master key is not base64: %w", err)
	}
	if len(key) != 32 {
		return nil, errors.New("vault: master key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Vault{aead: aead}, nil
}

// Seal encrypts plaintext. aad binds the ciphertext to its row (the secret
// name) so ciphertexts cannot be swapped between rows.
func (v *Vault) Seal(plaintext, aad []byte) []byte {
	nonce := make([]byte, v.aead.NonceSize())
	rand.Read(nonce)
	return v.aead.Seal(nonce, nonce, plaintext, aad)
}

func (v *Vault) Open(sealed, aad []byte) ([]byte, error) {
	ns := v.aead.NonceSize()
	if len(sealed) < ns {
		return nil, errors.New("vault: ciphertext too short")
	}
	return v.aead.Open(nil, sealed[:ns], sealed[ns:], aad)
}
