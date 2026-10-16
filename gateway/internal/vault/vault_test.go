package vault

import "testing"

func TestSealOpen(t *testing.T) {
	v, err := New(GenerateKey())
	if err != nil {
		t.Fatal(err)
	}
	ct := v.Seal([]byte("hunter2"), []byte("db-root"))
	pt, err := v.Open(ct, []byte("db-root"))
	if err != nil || string(pt) != "hunter2" {
		t.Fatalf("got %q %v", pt, err)
	}
	if _, err := v.Open(ct, []byte("other-row")); err == nil {
		t.Fatal("ciphertext opened under a different aad")
	}
}
