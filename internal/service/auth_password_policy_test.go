package service

import "testing"

func TestValidatePasswordPolicy(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{name: "valid", password: "Valid#Pass123", wantErr: false},
		{name: "too_short", password: "Aa1#short", wantErr: true},
		{name: "missing_upper", password: "valid#pass1234", wantErr: true},
		{name: "missing_lower", password: "VALID#PASS1234", wantErr: true},
		{name: "missing_digit", password: "Valid#Password", wantErr: true},
		{name: "missing_special", password: "ValidPass1234", wantErr: true},
	}
	for _, tc := range tests {
		err := validatePassword(tc.password)
		if tc.wantErr && err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
		if !tc.wantErr && err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.name, err)
		}
	}
}
