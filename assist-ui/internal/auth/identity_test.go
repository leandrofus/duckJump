package auth

import (
	"testing"
)

func TestDetectIdentity(t *testing.T) {
	id := DetectIdentity()
	if id.Username == "" {
		t.Fatalf("expected non-empty username, got empty")
	}
	if id.Hostname == "" {
		t.Fatalf("expected non-empty hostname, got empty")
	}
	if id.OS == "" {
		t.Fatalf("expected non-empty OS, got empty")
	}

	target := id.FullTargetName()
	if target == "" {
		t.Fatalf("expected non-empty FullTargetName")
	}
}

func TestFullTargetNameAD(t *testing.T) {
	id := UserIdentity{
		Username:       "micaela",
		Domain:         "CORP",
		AccountType:    AccountAD,
		IsDomainJoined: true,
	}

	expected := "CORP\\micaela"
	if actual := id.FullTargetName(); actual != expected {
		t.Fatalf("expected %q, got %q", expected, actual)
	}
}

func TestFullTargetNameLocal(t *testing.T) {
	id := UserIdentity{
		Username:    "admin",
		Domain:      "PC-WORK",
		AccountType: AccountLocal,
	}

	expected := "admin"
	if actual := id.FullTargetName(); actual != expected {
		t.Fatalf("expected %q, got %q", expected, actual)
	}
}
