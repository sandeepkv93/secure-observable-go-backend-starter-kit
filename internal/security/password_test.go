package security

import "testing"

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("Stronger#Pass123")
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}
	ok, err := VerifyPassword(hash, "Stronger#Pass123")
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if !ok {
		t.Fatal("expected password verification success")
	}
	ok, err = VerifyPassword(hash, "wrong-pass")
	if err != nil {
		t.Fatalf("verify wrong password errored: %v", err)
	}
	if ok {
		t.Fatal("expected password verification failure")
	}
}
