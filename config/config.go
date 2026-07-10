// Package config loads and layers gatekeeper TOML configuration.
//
// Config is harness-neutral: the same gatekeeper.toml is consulted by the
// claude, codex, and grok adapters. Paths are resolved with a harness-neutral
// canonical location plus a back-compatible ~/.claude fallback so existing
// Claude installs keep working unchanged.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/jim80net/gatekeeper-core/canonical"
)

// OnError values for the [on_error] knob.
const (
	OnErrorAbstain = "abstain" // default: on any gatekeeper error, emit no verdict
	OnErrorDeny    = "deny"    // opt-in hard posture: on any error, emit an explicit deny
)

// Config is the top-level configuration.
type Config struct {
	// OnError controls the verdict emitted on a gatekeeper error (unparseable
	// stdin, missing/unparseable config, bad rule regex, evaluate error,
	// panic). "abstain" (default) emits no verdict so the harness's native
	// permission system decides; "deny" emits an explicit deny. A clean
	// "no rule matched" is NOT an error and always abstains.
	OnError string `toml:"on_error"`
	Rules   []Rule `toml:"rules"`
}

// Rule is a single permission rule.
type Rule struct {
	Tool              string `toml:"tool"`
	Input             string `toml:"input"`
	Decision          string `toml:"decision"`
	Reason            string `toml:"reason"`
	Precondition      string `toml:"precondition,omitempty"`
	PreconditionMatch string `toml:"precondition_match,omitempty"`
}

// OnErrorDecision returns the canonical decision to emit on a gatekeeper error,
// per the on_error knob. Any value other than "deny" (including the empty
// default and an unrecognised value) resolves to Abstain — the safe posture
// that never decides FOR the native permission system.
func (c *Config) OnErrorDecision() canonical.Decision {
	if c != nil && c.OnError == OnErrorDeny {
		return canonical.Deny
	}
	return canonical.Abstain
}

// GlobalOnError returns the on_error decision from the GLOBAL config alone,
// best-effort. It returns canonical.Abstain on any problem (no global config,
// or an unparseable one). It is used on the error paths where the full
// (global+project) Load could not be trusted but a deployment's global
// on_error="deny" posture should still be honoured when it is readable.
func GlobalOnError() canonical.Decision {
	p := resolveGlobalPath()
	if p == "" {
		return canonical.Abstain
	}
	g, err := LoadFile(p)
	if err != nil {
		return canonical.Abstain
	}
	return g.OnErrorDecision()
}

// GlobalConfigPath returns the back-compatible global config write target,
// ~/.claude/gatekeeper.toml. Reads prefer the XDG canonical path when present
// (see resolveGlobalPath); writes stay at ~/.claude so existing Claude installs
// are undisturbed.
func GlobalConfigPath() string {
	homeDir, _ := os.UserHomeDir()
	if homeDir == "" {
		return ""
	}
	return filepath.Join(homeDir, ".claude", "gatekeeper.toml")
}

// xdgGlobalPath returns the harness-neutral XDG global config path,
// $XDG_CONFIG_HOME/gatekeeper/gatekeeper.toml (default ~/.config/...), or ""
// if the home directory cannot be determined.
func xdgGlobalPath() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "gatekeeper", "gatekeeper.toml")
	}
	homeDir, _ := os.UserHomeDir()
	if homeDir == "" {
		return ""
	}
	return filepath.Join(homeDir, ".config", "gatekeeper", "gatekeeper.toml")
}

// resolveGlobalPath returns the global config path to load: the XDG canonical
// path when it exists, otherwise the back-compat ~/.claude path. Returns ""
// when neither exists (no global config).
//
// A candidate is skipped ONLY when it is definitively absent (os.IsNotExist).
// Any other stat error (permission denied, transient I/O) does NOT silently
// fall through to the next candidate — the path is returned so Load surfaces
// the real read error via the on_error posture instead of quietly using a
// different config than the operator intended.
func resolveGlobalPath() string {
	for _, p := range []string{xdgGlobalPath(), GlobalConfigPath()} {
		if p == "" {
			continue
		}
		if pathPresent(p) {
			return p
		}
	}
	return ""
}

// pathPresent reports whether a config path should be treated as present: true
// when it exists, and also true on a non-ENOENT stat error (so the real error
// surfaces at read time rather than being masked as "not present").
func pathPresent(p string) bool {
	_, err := os.Stat(p)
	return err == nil || !os.IsNotExist(err)
}

// resolveProjectPath returns the project config overlay path for projectDir:
// the harness-neutral <dir>/.gatekeeper/gatekeeper.toml when it exists,
// otherwise the back-compat <dir>/.claude/gatekeeper.toml. Returns "" when
// neither exists.
func resolveProjectPath(projectDir string) string {
	if projectDir == "" {
		return ""
	}
	candidates := []string{
		filepath.Join(projectDir, ".gatekeeper", "gatekeeper.toml"),
		filepath.Join(projectDir, ".claude", "gatekeeper.toml"),
	}
	for _, p := range candidates {
		if pathPresent(p) {
			return p
		}
	}
	return ""
}

// EnsureGlobalConfig copies templatePath to the back-compat global config path
// (~/.claude/gatekeeper.toml) if no global config already exists (in either the
// XDG or the ~/.claude location). This provides seamless defaults on first run
// when installed as a plugin.
func EnsureGlobalConfig(templatePath string) error {
	if existing := resolveGlobalPath(); existing != "" {
		return nil // a global config already exists somewhere
	}

	dest := GlobalConfigPath()
	if dest == "" {
		return fmt.Errorf("cannot determine home directory")
	}

	data, err := os.ReadFile(templatePath)
	if err != nil {
		return fmt.Errorf("reading template: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	if err := os.WriteFile(dest, data, 0644); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	canonical.Debugf("installed default config: %s", dest)
	return nil
}

// Load builds the final config by layering the resolved global and project
// files. A MISSING config file is skipped silently (a clean absence, not an
// error); an UNPARSEABLE config file returns an error so the caller can apply
// its on_error posture. Later layers (project) override earlier (global) for
// scalar fields like on_error; rules accumulate.
func Load(projectDir string) (*Config, error) {
	cfg := &Config{}

	if globalPath := resolveGlobalPath(); globalPath != "" {
		g, err := LoadFile(globalPath)
		if err != nil {
			return nil, fmt.Errorf("global config: %w", err)
		}
		mergeInto(cfg, g)
		canonical.Debugf("loaded global config: %s (%d rules, on_error=%q)", globalPath, len(g.Rules), g.OnError)
	}

	if projectPath := resolveProjectPath(projectDir); projectPath != "" {
		p, err := LoadFile(projectPath)
		if err != nil {
			return nil, fmt.Errorf("project config: %w", err)
		}
		mergeInto(cfg, p)
		canonical.Debugf("loaded project config: %s (%d rules, on_error=%q)", projectPath, len(p.Rules), p.OnError)
	}

	canonical.Debugf("total rules: %d, on_error=%q", len(cfg.Rules), cfg.effectiveOnError())
	return cfg, nil
}

// mergeInto accumulates src's rules into dst and lets a non-empty src.OnError
// override dst.OnError (last layer wins for the scalar knob).
func mergeInto(dst, src *Config) {
	dst.Rules = append(dst.Rules, src.Rules...)
	if src.OnError != "" {
		dst.OnError = src.OnError
	}
}

// effectiveOnError returns the on_error value for logging, defaulting to
// "abstain" when unset.
func (c *Config) effectiveOnError() string {
	if c.OnError == "" {
		return OnErrorAbstain
	}
	return c.OnError
}

// LoadFile parses a TOML config from the given path.
func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &cfg, nil
}
