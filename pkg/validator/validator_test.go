package validator

import (
	"testing"

	"github.com/go-playground/validator/v10"
)

func TestIsWebProxyAlias(t *testing.T) {
	valid := []string{"a", "8080a", "0-a", "1-2-3x", "nats-course", "tomvit-1", "a-b-c", "x1234567890123456789012345678901234567890123456789012345678901y"}
	for _, s := range valid {
		if !IsWebProxyAlias(s) {
			t.Errorf("IsWebProxyAlias(%q) = false, want true", s)
		}
	}
	invalid := []string{"", "0", "8080", "-a", "a-", "a--b", "xn--abc", "Nats", "a.b", "a_b", "a b", "ä",
		"x12345678901234567890123456789012345678901234567890123456789012y"}
	for _, s := range invalid {
		if IsWebProxyAlias(s) {
			t.Errorf("IsWebProxyAlias(%q) = true, want false", s)
		}
	}
}

func TestWebProxyAliasTag(t *testing.T) {
	type req struct {
		Alias    string  `validate:"omitempty,webproxyalias"`
		AliasPtr *string `validate:"omitempty,webproxyalias"`
	}
	v := validator.New()
	RegisterCustomValidators(v)

	empty, bad, good := "", "Bad--Alias", "good"
	cases := []struct {
		name string
		in   req
		ok   bool
	}{
		{"all unset", req{}, true},
		{"valid", req{Alias: "good", AliasPtr: &good}, true},
		{"pointer to empty clears", req{AliasPtr: &empty}, true},
		{"invalid value", req{Alias: "a--b"}, false},
		{"invalid pointer", req{AliasPtr: &bad}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := v.Struct(c.in)
			if (err == nil) != c.ok {
				t.Fatalf("Struct(%+v) err = %v, want ok=%v", c.in, err, c.ok)
			}
		})
	}
}
