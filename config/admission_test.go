package config_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jim80net/gatekeeper-core/canonical"
	"github.com/jim80net/gatekeeper-core/config"
	"github.com/jim80net/gatekeeper-core/engine"
)

func writeAdmissionConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gatekeeper.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadFileRejectsPreconditionWithoutMatchBeforeEvaluate(t *testing.T) {
	path := writeAdmissionConfig(t, `
[[rules]]
tool = "^Bash$"
input = ".*"
decision = "deny"
precondition = "printf ready"
`)

	cfg, err := config.LoadFile(path)
	if err != nil {
		if !strings.Contains(err.Error(), "precondition and precondition_match must be set together") {
			t.Fatalf("LoadFile() error = %q, want paired precondition error", err)
		}
		return
	}

	// This deliberately crosses the full public load -> construct -> evaluate
	// boundary. Before admission validation was wired in, Evaluate reached a
	// nil PreconditionRegex dereference here.
	eng, newErr := engine.New(cfg, false)
	if newErr != nil {
		t.Fatalf("LoadFile() accepted invalid config; Engine.New() error = %v", newErr)
	}
	_, evalErr := eng.Evaluate(&canonical.ToolCall{Tool: canonical.ToolBash, InputString: "echo hi"})
	t.Fatalf("LoadFile() accepted an unpaired precondition; Evaluate() error = %v", evalErr)
}

func TestLoadFileRejectsPreconditionMatchWithoutCommand(t *testing.T) {
	path := writeAdmissionConfig(t, `
[[rules]]
tool = "^Bash$"
input = ".*"
decision = "deny"
precondition_match = "ready"
`)

	_, err := config.LoadFile(path)
	if err == nil || !strings.Contains(err.Error(), "precondition and precondition_match must be set together") {
		t.Fatalf("LoadFile() error = %v, want paired precondition error", err)
	}
}

func TestLoadFileRejectsUnknownTOMLField(t *testing.T) {
	path := writeAdmissionConfig(t, `
[[rules]]
tool = "^Bash$"
input = ".*"
decision = "deny"
decison = "allow"
`)

	_, err := config.LoadFile(path)
	if err == nil || !strings.Contains(err.Error(), "unknown TOML field") {
		t.Fatalf("LoadFile() error = %v, want unknown TOML field error", err)
	}
}

func TestLoadFileRejectsInvalidRuleRegexes(t *testing.T) {
	tests := []struct {
		name      string
		tool      string
		input     string
		extra     string
		wantError string
	}{
		{name: "tool", tool: "(", input: ".*", wantError: "invalid tool regex"},
		{name: "input", tool: "^Bash$", input: "(", wantError: "invalid input regex"},
		{
			name:      "precondition_match",
			tool:      "^Bash$",
			input:     ".*",
			extra:     "precondition = \"printf ready\"\nprecondition_match = \"(\"",
			wantError: "invalid precondition_match regex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := fmt.Sprintf("[[rules]]\ntool = %q\ninput = %q\ndecision = \"deny\"\n%s\n", tt.tool, tt.input, tt.extra)
			_, err := config.LoadFile(writeAdmissionConfig(t, body))
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("LoadFile() error = %v, want %q", err, tt.wantError)
			}
		})
	}
}
