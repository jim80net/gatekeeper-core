package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jim80net/gatekeeper-core/config"
)

func TestLoadLayered(t *testing.T) {
	// Create a temp dir acting as $HOME/.claude/
	homeDir := t.TempDir()
	globalDir := filepath.Join(homeDir, ".claude")
	os.MkdirAll(globalDir, 0755)

	globalConfig := `
[[rules]]
tool  = 'Bash'
input = '^custom-tool\s'
decision = "allow"
reason = "Custom global rule"
`
	os.WriteFile(filepath.Join(globalDir, "gatekeeper.toml"), []byte(globalConfig), 0644)

	// Create a project dir with its own config.
	projectDir := t.TempDir()
	projectClaudeDir := filepath.Join(projectDir, ".claude")
	os.MkdirAll(projectClaudeDir, 0755)

	projectConfig := `
[[rules]]
tool  = 'Bash'
input = '^project-tool\s'
decision = "deny"
reason = "Project deny rule"
`
	os.WriteFile(filepath.Join(projectClaudeDir, "gatekeeper.toml"), []byte(projectConfig), 0644)

	// Override HOME for this test.
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", homeDir)
	defer os.Setenv("HOME", origHome)

	cfg, err := config.Load(projectDir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Should have global + project rules.
	foundGlobal := false
	foundProject := false
	for _, r := range cfg.Rules {
		if r.Reason == "Custom global rule" {
			foundGlobal = true
		}
		if r.Reason == "Project deny rule" {
			foundProject = true
		}
	}
	if !foundGlobal {
		t.Error("global rule not found in merged config")
	}
	if !foundProject {
		t.Error("project rule not found in merged config")
	}
}

func TestLoadNoConfig(t *testing.T) {
	homeDir := t.TempDir()

	origHome := os.Getenv("HOME")
	os.Setenv("HOME", homeDir)
	defer os.Setenv("HOME", origHome)

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(cfg.Rules) != 0 {
		t.Fatalf("expected 0 rules with no config files, got %d", len(cfg.Rules))
	}
}

func TestEnsureGlobalConfigCreatesFile(t *testing.T) {
	homeDir := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", homeDir)
	defer os.Setenv("HOME", origHome)

	// Create a template file.
	templateDir := t.TempDir()
	templatePath := filepath.Join(templateDir, "gatekeeper.toml")
	os.WriteFile(templatePath, []byte("[[rules]]\ntool = 'Bash'\ninput = '.*'\ndecision = \"allow\"\nreason = \"test\"\n"), 0644)

	err := config.EnsureGlobalConfig(templatePath)
	if err != nil {
		t.Fatalf("EnsureGlobalConfig: %v", err)
	}

	dest := filepath.Join(homeDir, ".claude", "gatekeeper.toml")
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("reading installed config: %v", err)
	}
	if len(data) == 0 {
		t.Error("installed config is empty")
	}
}

func TestEnsureGlobalConfigSkipsExisting(t *testing.T) {
	homeDir := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", homeDir)
	defer os.Setenv("HOME", origHome)

	// Pre-create the config with custom content.
	claudeDir := filepath.Join(homeDir, ".claude")
	os.MkdirAll(claudeDir, 0755)
	existing := []byte("# my custom config\n")
	os.WriteFile(filepath.Join(claudeDir, "gatekeeper.toml"), existing, 0644)

	// Create a template with different content.
	templateDir := t.TempDir()
	templatePath := filepath.Join(templateDir, "gatekeeper.toml")
	os.WriteFile(templatePath, []byte("# template content\n"), 0644)

	err := config.EnsureGlobalConfig(templatePath)
	if err != nil {
		t.Fatalf("EnsureGlobalConfig: %v", err)
	}

	// Verify the existing file was NOT overwritten.
	data, _ := os.ReadFile(filepath.Join(claudeDir, "gatekeeper.toml"))
	if string(data) != string(existing) {
		t.Errorf("existing config was overwritten: got %q", string(data))
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.toml")

	content := `
[[rules]]
tool  = 'Bash'
input = '^echo\s'
decision = "allow"
reason = "Echo"
`
	os.WriteFile(path, []byte(content), 0644)

	cfg, err := config.LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}
	if cfg.Rules[0].Reason != "Echo" {
		t.Errorf("unexpected rule: %q", cfg.Rules[0].Reason)
	}
}
