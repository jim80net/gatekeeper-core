package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jim80net/gatekeeper-core/canonical"
	"github.com/jim80net/gatekeeper-core/config"
)

func setHome(t *testing.T) string {
	t.Helper()
	homeDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", origHome) })
	os.Setenv("HOME", homeDir)
	// Prevent a host XDG_CONFIG_HOME from shadowing the test's ~/.claude config.
	origXDG, had := os.LookupEnv("XDG_CONFIG_HOME")
	os.Unsetenv("XDG_CONFIG_HOME")
	t.Cleanup(func() {
		if had {
			os.Setenv("XDG_CONFIG_HOME", origXDG)
		}
	})
	return homeDir
}

func writeClaudeGlobal(t *testing.T, homeDir, content string) {
	t.Helper()
	dir := filepath.Join(homeDir, ".claude")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "gatekeeper.toml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestOnErrorDecision(t *testing.T) {
	tests := []struct {
		onError string
		want    canonical.Decision
	}{
		{"", canonical.Abstain},        // default
		{"abstain", canonical.Abstain}, // explicit
		{"deny", canonical.Deny},
		{"bogus", canonical.Abstain}, // unrecognised -> safe default
	}
	for _, tt := range tests {
		cfg := &config.Config{OnError: tt.onError}
		if got := cfg.OnErrorDecision(); got != tt.want {
			t.Errorf("OnError=%q -> %s, want %s", tt.onError, got, tt.want)
		}
	}
}

func TestLoadReadsOnError(t *testing.T) {
	homeDir := setHome(t)
	writeClaudeGlobal(t, homeDir, "on_error = \"deny\"\n[[rules]]\ntool='Bash'\ninput='.*'\ndecision=\"allow\"\nreason=\"x\"\n")

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OnErrorDecision() != canonical.Deny {
		t.Errorf("on_error not read from global config; got %s", cfg.OnErrorDecision())
	}
}

// TestProjectOverridesOnError confirms the project layer overrides the global
// on_error scalar while rules from both accumulate.
func TestProjectOverridesOnError(t *testing.T) {
	homeDir := setHome(t)
	writeClaudeGlobal(t, homeDir, "on_error = \"abstain\"\n")

	projectDir := t.TempDir()
	pClaude := filepath.Join(projectDir, ".claude")
	os.MkdirAll(pClaude, 0755)
	os.WriteFile(filepath.Join(pClaude, "gatekeeper.toml"), []byte("on_error = \"deny\"\n"), 0644)

	cfg, err := config.Load(projectDir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OnErrorDecision() != canonical.Deny {
		t.Errorf("project on_error did not override global; got %s", cfg.OnErrorDecision())
	}
}

// TestLoadErrorsOnUnparseableButNotMissing pins the split that drives the
// on_error path: a MISSING config is a clean absence (no error); an UNPARSEABLE
// one is an error the caller applies on_error to.
func TestLoadErrorsOnUnparseableButNotMissing(t *testing.T) {
	homeDir := setHome(t)

	// Missing: no error, empty config.
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("missing config should not error, got %v", err)
	}
	if len(cfg.Rules) != 0 || cfg.OnErrorDecision() != canonical.Abstain {
		t.Errorf("missing config: got %d rules, on_error %s", len(cfg.Rules), cfg.OnErrorDecision())
	}

	// Unparseable: error.
	writeClaudeGlobal(t, homeDir, "this is = = not toml [")
	if _, err := config.Load(""); err == nil {
		t.Error("unparseable config should return an error")
	}
}

func TestGlobalOnError(t *testing.T) {
	homeDir := setHome(t)

	// No config -> Abstain (best-effort default).
	if got := config.GlobalOnError(); got != canonical.Abstain {
		t.Errorf("no config: GlobalOnError = %s, want abstain", got)
	}

	// Readable deny global -> Deny.
	writeClaudeGlobal(t, homeDir, "on_error = \"deny\"\n")
	if got := config.GlobalOnError(); got != canonical.Deny {
		t.Errorf("deny config: GlobalOnError = %s, want deny", got)
	}

	// Unparseable global -> Abstain (cannot trust it).
	writeClaudeGlobal(t, homeDir, "= = broken")
	if got := config.GlobalOnError(); got != canonical.Abstain {
		t.Errorf("broken config: GlobalOnError = %s, want abstain", got)
	}
}

// TestXDGPathPreferredWhenPresent verifies the harness-neutral XDG global path
// takes precedence over the ~/.claude back-compat path.
func TestXDGPathPreferredWhenPresent(t *testing.T) {
	homeDir := setHome(t)
	xdg := t.TempDir()
	os.Setenv("XDG_CONFIG_HOME", xdg)
	t.Cleanup(func() { os.Unsetenv("XDG_CONFIG_HOME") })

	// Back-compat path says allow-only; XDG path says deny — XDG must win.
	writeClaudeGlobal(t, homeDir, "on_error = \"abstain\"\n")
	xdgDir := filepath.Join(xdg, "gatekeeper")
	os.MkdirAll(xdgDir, 0755)
	os.WriteFile(filepath.Join(xdgDir, "gatekeeper.toml"), []byte("on_error = \"deny\"\n"), 0644)

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OnErrorDecision() != canonical.Deny {
		t.Errorf("XDG path not preferred; got %s", cfg.OnErrorDecision())
	}
}

// TestGatekeeperProjectDirPreferred verifies the harness-neutral .gatekeeper
// project overlay takes precedence over the .claude back-compat overlay.
func TestGatekeeperProjectDirPreferred(t *testing.T) {
	setHome(t)
	projectDir := t.TempDir()

	claudeDir := filepath.Join(projectDir, ".claude")
	os.MkdirAll(claudeDir, 0755)
	os.WriteFile(filepath.Join(claudeDir, "gatekeeper.toml"),
		[]byte("[[rules]]\ntool='Bash'\ninput='claude-only'\ndecision=\"deny\"\nreason=\"claude\"\n"), 0644)

	gkDir := filepath.Join(projectDir, ".gatekeeper")
	os.MkdirAll(gkDir, 0755)
	os.WriteFile(filepath.Join(gkDir, "gatekeeper.toml"),
		[]byte("[[rules]]\ntool='Bash'\ninput='gk-only'\ndecision=\"deny\"\nreason=\"gk\"\n"), 0644)

	cfg, err := config.Load(projectDir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Only the .gatekeeper overlay should be loaded (it wins; .claude ignored).
	for _, r := range cfg.Rules {
		if r.Reason == "claude" {
			t.Error(".claude overlay loaded despite .gatekeeper present")
		}
	}
	found := false
	for _, r := range cfg.Rules {
		if r.Reason == "gk" {
			found = true
		}
	}
	if !found {
		t.Error(".gatekeeper overlay not loaded")
	}
}
