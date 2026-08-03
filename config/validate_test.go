package config

import (
	"strings"
	"testing"
)

func TestValidateAcceptsValidConfig(t *testing.T) {
	cfg := &Config{
		OnError: OnErrorDeny,
		Rules: []Rule{{
			Tool:              "^Bash$",
			Input:             `git\s+push`,
			Decision:          "deny",
			Precondition:      "git branch --show-current",
			PreconditionMatch: `^(main|master)$`,
		}},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateReportsAllProblems(t *testing.T) {
	cfg := &Config{
		OnError: "allow",
		Rules: []Rule{{
			Tool:              `(`,
			Input:             `(`,
			Decision:          "maybe",
			PreconditionMatch: `(`,
		}},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want multiple problems")
	}
	for _, want := range []string{
		`on_error must be`,
		`rule 1: invalid tool regex`,
		`rule 1: invalid input regex`,
		`rule 1: decision must be`,
		`rule 1: precondition and precondition_match must be set together`,
		`rule 1: invalid precondition_match regex`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Validate() error = %q, want substring %q", err, want)
		}
	}
}

func TestValidateNilConfig(t *testing.T) {
	var cfg *Config
	if err := cfg.Validate(); err == nil || err.Error() != "config is nil" {
		t.Fatalf("Validate() error = %v, want config is nil", err)
	}
}
