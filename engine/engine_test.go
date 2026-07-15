package engine_test

import (
	"context"
	"testing"

	"github.com/jim80net/gatekeeper-core/canonical"
	"github.com/jim80net/gatekeeper-core/config"
	"github.com/jim80net/gatekeeper-core/engine"
)

func bashInput(cmd string) *canonical.ToolCall {
	return &canonical.ToolCall{Tool: canonical.ToolBash, InputString: cmd, CWD: "/tmp"}
}

func readInput(path string) *canonical.ToolCall {
	return &canonical.ToolCall{Tool: canonical.ToolRead, InputString: path, CWD: "/tmp"}
}

// toolInput models a non-Bash tool whose matchable string is its own name
// (the canonical default for tools like Glob/Grep/Edit with no salient input).
func toolInput(tool string) *canonical.ToolCall {
	return &canonical.ToolCall{Tool: tool, InputString: tool, CWD: "/tmp"}
}

func newEngine(t *testing.T, rules []config.Rule) *engine.Engine {
	t.Helper()
	cfg := &config.Config{Rules: rules}
	eng, err := engine.New(cfg, false)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	return eng
}

func newEngineWithPrecondition(t *testing.T, rules []config.Rule, cmdOutput string) *engine.Engine {
	t.Helper()
	eng := newEngine(t, rules)
	eng.SetExecCommand(func(ctx context.Context, cwd, command, toolInput string) (string, error) {
		return cmdOutput, nil
	})
	return eng
}

func TestDenyAlwaysWins(t *testing.T) {
	eng := newEngine(t, []config.Rule{
		{Tool: "Bash", Input: "^git\\s", Decision: "allow", Reason: "allow git"},
		{Tool: "Bash", Input: "git\\s+reset\\s+--hard", Decision: "deny", Reason: "deny reset"},
	})

	v, err := eng.Evaluate(bashInput("git reset --hard"))
	if err != nil {
		t.Fatal(err)
	}
	if v.Decision != canonical.Deny {
		t.Errorf("expected deny for git reset --hard, got %s", v.Decision)
	}
}

func TestVerdictCarriesMatchingRuleProvenance(t *testing.T) {
	eng := newEngine(t, []config.Rule{
		{Tool: "Bash", Input: "danger", Decision: "deny", Reason: "blocked", Source: "/policy/global.toml", SourceIndex: 3},
		{Tool: "Bash", Input: "danger", Decision: "allow", Reason: "allowed", Source: "/policy/project.toml", SourceIndex: 2},
	})

	v, err := eng.Evaluate(&canonical.ToolCall{Tool: canonical.ToolBash, InputString: "danger"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Decision != canonical.Deny {
		t.Fatalf("decision = %s, want deny", v.Decision)
	}
	if len(v.Rules) != 1 || v.Rules[0].Source != "/policy/global.toml" || v.Rules[0].Index != 3 {
		t.Fatalf("provenance = %#v, want global rule 3 only", v.Rules)
	}
}

func TestAllowWhenMatched(t *testing.T) {
	eng := newEngine(t, []config.Rule{
		{Tool: "Bash", Input: "^git\\s", Decision: "allow", Reason: "allow git"},
	})

	v, err := eng.Evaluate(bashInput("git status"))
	if err != nil {
		t.Fatal(err)
	}
	if v.Decision != canonical.Allow {
		t.Errorf("expected allow for git status, got %s", v.Decision)
	}
}

func TestAbstainWhenNoMatch(t *testing.T) {
	eng := newEngine(t, []config.Rule{
		{Tool: "Bash", Input: "^git\\s", Decision: "allow", Reason: "allow git"},
	})

	v, err := eng.Evaluate(bashInput("some-unknown-command"))
	if err != nil {
		t.Fatal(err)
	}
	if v.Decision != canonical.Abstain {
		t.Errorf("expected abstain for unmatched command, got %s", v.Decision)
	}
}

func TestPreconditionMatches(t *testing.T) {
	eng := newEngineWithPrecondition(t, []config.Rule{
		{
			Tool:              "Bash",
			Input:             "\\bgit\\s+push\\b",
			Precondition:      "git branch --show-current",
			PreconditionMatch: "^(main|master)$",
			Decision:          "deny",
			Reason:            "push on main",
		},
	}, "main\n")

	v, err := eng.Evaluate(bashInput("git push"))
	if err != nil {
		t.Fatal(err)
	}
	if v.Decision != canonical.Deny {
		t.Errorf("expected deny when on main branch, got %s", v.Decision)
	}
}

func TestPreconditionDoesNotMatch(t *testing.T) {
	eng := newEngineWithPrecondition(t, []config.Rule{
		{
			Tool:              "Bash",
			Input:             "\\bgit\\s+push\\b",
			Precondition:      "git branch --show-current",
			PreconditionMatch: "^(main|master)$",
			Decision:          "deny",
			Reason:            "push on main",
		},
	}, "feature-branch\n")

	v, err := eng.Evaluate(bashInput("git push"))
	if err != nil {
		t.Fatal(err)
	}
	if v.Decision != canonical.Abstain {
		t.Errorf("expected abstain when on feature branch, got %s", v.Decision)
	}
}

func TestPreconditionWithCDPrefix(t *testing.T) {
	// When the command is "cd /other/repo && git push", the precondition
	// should run with "cd /other/repo && git branch --show-current",
	// NOT just "git branch --show-current" in the session CWD.
	rules := []config.Rule{
		{
			Tool:              "Bash",
			Input:             "\\bgit\\s+push\\b(?!.*\\b(main|master)\\b)",
			Precondition:      "git branch --show-current",
			PreconditionMatch: "^(main|master)$",
			Decision:          "deny",
			Reason:            "push on main",
		},
	}

	t.Run("cd to repo on feature branch allows push", func(t *testing.T) {
		eng := newEngine(t, rules)
		eng.SetExecCommand(func(ctx context.Context, cwd, command, toolInput string) (string, error) {
			// Verify the cd prefix was prepended to the precondition.
			if command != "cd /other/repo && git branch --show-current" {
				t.Errorf("expected cd-prefixed precondition, got: %s", command)
			}
			return "feature-branch\n", nil
		})

		v, err := eng.Evaluate(bashInput("cd /other/repo && git push -u origin feature-branch"))
		if err != nil {
			t.Fatal(err)
		}
		if v.Decision != canonical.Abstain {
			t.Errorf("expected abstain (no deny) when cd'd repo is on feature branch, got %s", v.Decision)
		}
	})

	t.Run("cd to repo on main still denies push", func(t *testing.T) {
		eng := newEngine(t, rules)
		eng.SetExecCommand(func(ctx context.Context, cwd, command, toolInput string) (string, error) {
			if command != "cd /other/repo && git branch --show-current" {
				t.Errorf("expected cd-prefixed precondition, got: %s", command)
			}
			return "main\n", nil
		})

		v, err := eng.Evaluate(bashInput("cd /other/repo && git push"))
		if err != nil {
			t.Fatal(err)
		}
		if v.Decision != canonical.Deny {
			t.Errorf("expected deny when cd'd repo is on main, got %s", v.Decision)
		}
	})

	t.Run("no cd prefix keeps original behavior", func(t *testing.T) {
		eng := newEngine(t, rules)
		eng.SetExecCommand(func(ctx context.Context, cwd, command, toolInput string) (string, error) {
			if command != "git branch --show-current" {
				t.Errorf("expected bare precondition, got: %s", command)
			}
			return "main\n", nil
		})

		v, err := eng.Evaluate(bashInput("git push"))
		if err != nil {
			t.Fatal(err)
		}
		if v.Decision != canonical.Deny {
			t.Errorf("expected deny when CWD is on main, got %s", v.Decision)
		}
	})
}

func TestExtractCDPrefix(t *testing.T) {
	tests := []struct {
		command string
		want    string
	}{
		{"cd /tmp/foo && git push", "cd /tmp/foo &&"},
		{"cd /tmp/foo && git push -u origin main", "cd /tmp/foo &&"},
		{"cd ~/projects/bar && git status", "cd ~/projects/bar &&"},
		{"git push", ""},
		{"echo cd /tmp && git push", ""},
		{"cd /tmp/foo", ""},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got := engine.ExtractCDPrefix(tt.command)
			if got != tt.want {
				t.Errorf("extractCDPrefix(%q) = %q, want %q", tt.command, got, tt.want)
			}
		})
	}
}

func TestStripHeredocs(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    string
	}{
		{
			name:    "no heredoc",
			command: "git status",
			want:    "git status",
		},
		{
			name:    "unquoted heredoc",
			command: "git commit -m \"$(cat <<EOF\nThis mentions rm -rf dist\nEOF\n)\"",
			want:    "git commit -m \"$(cat <<EOF\n)\"",
		},
		{
			name:    "single-quoted heredoc",
			command: "git commit -m \"$(cat <<'EOF'\nrm -rf /tmp/stuff\ngit reset --hard\nEOF\n)\"",
			want:    "git commit -m \"$(cat <<'EOF'\n)\"",
		},
		{
			name:    "double-quoted heredoc",
			command: "gh pr create --body \"$(cat <<\"EOF\"\nDROP TABLE users\nEOF\n)\"",
			want:    "gh pr create --body \"$(cat <<\"EOF\"\n)\"",
		},
		{
			name:    "heredoc with dash",
			command: "cat <<-MARKER\n\tindented content with rm -rf\nMARKER",
			want:    "cat <<-MARKER",
		},
		{
			name:    "multiline command without heredoc",
			command: "echo hello &&\ngit push",
			want:    "echo hello &&\ngit push",
		},
		{
			name:    "command after heredoc preserved",
			command: "cat <<EOF\nheredoc body\nEOF\necho after",
			want:    "cat <<EOF\necho after",
		},
		{
			name:    "bash heredoc preserved",
			command: "bash <<'EOF'\nrm -rf /\nEOF",
			want:    "bash <<'EOF'\nrm -rf /\nEOF",
		},
		{
			name:    "sh heredoc preserved",
			command: "sh <<EOF\nrm -rf /tmp/stuff\nEOF",
			want:    "sh <<EOF\nrm -rf /tmp/stuff\nEOF",
		},
		{
			name:    "python heredoc preserved",
			command: "python3 <<'SCRIPT'\nimport os; os.system('rm -rf /')\nSCRIPT",
			want:    "python3 <<'SCRIPT'\nimport os; os.system('rm -rf /')\nSCRIPT",
		},
		{
			name:    "pipe to bash heredoc preserved",
			command: "echo something; bash <<'EOF'\nrm -rf /\nEOF",
			want:    "echo something; bash <<'EOF'\nrm -rf /\nEOF",
		},
		{
			name:    "cat heredoc still stripped",
			command: "cat <<'EOF'\nrm -rf /\nEOF",
			want:    "cat <<'EOF'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := engine.StripHeredocs(tt.command)
			if got != tt.want {
				t.Errorf("StripHeredocs:\n  input: %q\n  got:   %q\n  want:  %q", tt.command, got, tt.want)
			}
		})
	}
}

func TestHeredocContentDoesNotTriggerDeny(t *testing.T) {
	eng := newEngine(t, []config.Rule{
		{Tool: "Bash", Input: `\brm\s+(-[a-zA-Z]*r|--recursive)`, Decision: "deny", Reason: "recursive delete"},
		{Tool: "Bash", Input: `git\s+reset\s+--hard`, Decision: "deny", Reason: "hard reset"},
		{Tool: "Bash", Input: `(?si)(?=.*\b(?:psql|mysql|mariadb|sqlite3|mongosh|mongo|redis-cli|cqlsh|duckdb|cockroach|mycli|pgcli|litecli)\b).*\b(DROP|TRUNCATE|DELETE\s+FROM)\b`, Decision: "deny", Reason: "destructive SQL"},
		{Tool: "Bash", Input: `(?:^|[|;&]\s*)git\s`, Decision: "allow", Reason: "git"},
		{Tool: "Bash", Input: `(?:^|[|;&]\s*)gh\s`, Decision: "allow", Reason: "gh"},
	})

	tests := []struct {
		name string
		cmd  string
		want canonical.Decision
	}{
		{
			name: "commit message mentioning rm -rf",
			cmd:  "git commit -m \"$(cat <<'EOF'\nfeat: allow rm -rf on build dirs\nEOF\n)\"",
			want: canonical.Allow,
		},
		{
			name: "PR body mentioning DROP TABLE",
			cmd:  "gh pr create --body \"$(cat <<'EOF'\nThis fixes the DROP TABLE issue\nEOF\n)\"",
			want: canonical.Allow,
		},
		{
			name: "commit message mentioning git reset --hard",
			cmd:  "git commit -m \"$(cat <<'EOF'\nRevert git reset --hard behavior\nEOF\n)\"",
			want: canonical.Allow,
		},
		{
			name: "actual rm -rf still denied",
			cmd:  "rm -rf /tmp/stuff",
			want: canonical.Deny,
		},
		{
			name: "bash heredoc with rm -rf denied",
			cmd:  "bash <<'EOF'\nrm -rf /\nEOF",
			want: canonical.Deny,
		},
		{
			name: "sh heredoc with git reset --hard denied",
			cmd:  "sh <<'EOF'\ngit reset --hard\nEOF",
			want: canonical.Deny,
		},
		{
			name: "python heredoc with DROP TABLE no db tool - no deny",
			cmd:  "python3 <<'EOF'\nDROP TABLE users\nEOF",
			want: canonical.Abstain, // no database CLI tool in command, SQL rule doesn't match
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := eng.Evaluate(bashInput(tt.cmd))
			if err != nil {
				t.Fatal(err)
			}
			if v.Decision != tt.want {
				t.Errorf("got %s (%s), want %s", v.Decision, v.Reason, tt.want)
			}
		})
	}
}

func TestToolMatching(t *testing.T) {
	eng := newEngine(t, []config.Rule{
		{Tool: "Read|Glob|Grep", Input: ".*", Decision: "allow", Reason: "browsing"},
	})

	for _, tool := range []string{"Read", "Glob", "Grep"} {
		v, err := eng.Evaluate(toolInput(tool))
		if err != nil {
			t.Fatal(err)
		}
		if v.Decision != canonical.Allow {
			t.Errorf("expected allow for tool %s, got %s", tool, v.Decision)
		}
	}

	// Bash should not match.
	v, err := eng.Evaluate(bashInput("ls"))
	if err != nil {
		t.Fatal(err)
	}
	if v.Decision != canonical.Abstain {
		t.Errorf("expected abstain for Bash (not in Read|Glob|Grep), got %s", v.Decision)
	}
}

func TestCredentialFileDeny(t *testing.T) {
	eng := newEngine(t, []config.Rule{
		{Tool: "Read", Input: `(^|/)\.env(\..*)?$|\.envrc$|key\.json$|id_rsa|id_ed25519|\.pem$|credentials$|\.secret`, Decision: "deny", Reason: "creds"},
		{Tool: "Read|Glob|Grep", Input: ".*", Decision: "allow", Reason: "browsing"},
	})

	denyPaths := []string{
		"/home/user/.env",
		"/project/.env.local",
		"/home/user/.envrc",
		"/secrets/service-key.json",
		"/home/user/.ssh/id_rsa",
		"/home/user/.ssh/id_ed25519",
		"/etc/ssl/cert.pem",
		"/app/credentials",
		"/app/.secret",
	}

	for _, p := range denyPaths {
		v, err := eng.Evaluate(readInput(p))
		if err != nil {
			t.Fatal(err)
		}
		if v.Decision != canonical.Deny {
			t.Errorf("expected deny for Read %s, got %s", p, v.Decision)
		}
	}

	// Safe file should be allowed.
	v, err := eng.Evaluate(readInput("/project/src/main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if v.Decision != canonical.Allow {
		t.Errorf("expected allow for main.go, got %s", v.Decision)
	}
}

func TestInvalidRuleRegex(t *testing.T) {
	_, err := engine.New(&config.Config{Rules: []config.Rule{
		{Tool: "[invalid", Input: ".*", Decision: "allow", Reason: "bad"},
	}}, false)
	if err == nil {
		t.Error("expected error for invalid tool regex")
	}

	_, err = engine.New(&config.Config{Rules: []config.Rule{
		{Tool: "Bash", Input: "[invalid", Decision: "allow", Reason: "bad"},
	}}, false)
	if err == nil {
		t.Error("expected error for invalid input regex")
	}
}

func TestInvalidDecision(t *testing.T) {
	_, err := engine.New(&config.Config{Rules: []config.Rule{
		{Tool: "Bash", Input: ".*", Decision: "maybe", Reason: "bad"},
	}}, false)
	if err == nil {
		t.Error("expected error for invalid decision")
	}
}

// TestDefaultRules validates the shipped default rules against realistic commands.
func TestDefaultRules(t *testing.T) {
	cfg, err := config.LoadFile("../gatekeeper.toml")
	if err != nil {
		t.Fatalf("LoadFile(gatekeeper.toml): %v", err)
	}

	eng, err := engine.New(cfg, false)
	if err != nil {
		t.Fatalf("engine.New with defaults: %v", err)
	}

	// Override precondition exec so tests don't shell out.
	eng.SetExecCommand(func(ctx context.Context, cwd, command, toolInput string) (string, error) {
		// Default: not on main.
		return "feature-branch\n", nil
	})

	tests := []struct {
		name  string
		input *canonical.ToolCall
		want  canonical.Decision
	}{
		// Deny cases
		{"deny git reset --hard", bashInput("git reset --hard HEAD~1"), canonical.Deny},
		{"deny git clean -fd", bashInput("git clean -fd"), canonical.Deny},
		{"deny git push --force", bashInput("git push --force origin feature"), canonical.Deny},
		{"deny git push -f", bashInput("git push -f origin feature"), canonical.Deny},
		{"deny git commit --amend", bashInput("git commit --amend -m 'fix'"), canonical.Deny},
		{"deny git push origin main", bashInput("git push origin main"), canonical.Deny},
		{"deny git push origin master", bashInput("git push origin master"), canonical.Deny},
		{"deny git branch -D", bashInput("git branch -D feature-branch"), canonical.Deny},
		{"deny rm -rf", bashInput("rm -rf /tmp/stuff"), canonical.Deny},
		{"deny rm -r", bashInput("rm -r dir/"), canonical.Deny},
		{"deny rm --recursive", bashInput("rm --recursive dir/"), canonical.Deny},
		{"allow rm files in dist/", bashInput("rm dist/main.js dist/app.wasm"), canonical.Allow},
		{"allow rm files in build/", bashInput("rm build/output.bin"), canonical.Allow},
		{"deny sed", bashInput("sed -i 's/foo/bar/' file.txt"), canonical.Deny},
		{"deny awk", bashInput("awk '{print $1}' file.txt"), canonical.Deny},
		{"deny DROP TABLE via psql", bashInput("psql -c 'DROP TABLE users'"), canonical.Deny},
		{"deny TRUNCATE via mysql", bashInput("mysql -e 'TRUNCATE TABLE logs'"), canonical.Deny},
		{"deny DELETE FROM via sqlite3", bashInput("sqlite3 db.sqlite 'DELETE FROM users'"), canonical.Deny},
		{"deny DROP piped to psql", bashInput("echo 'DROP TABLE users' | psql"), canonical.Deny},
		{"allow drop in commit msg", bashInput("git commit -m 'fix: drop old feature'"), canonical.Allow},
		{"allow drop in echo", bashInput("echo 'drop this thing'"), canonical.Allow},
		{"deny cat .env", bashInput("cat .env"), canonical.Deny},
		{"deny read .env", readInput("/project/.env"), canonical.Deny},
		{"deny read id_rsa", readInput("/home/user/.ssh/id_rsa"), canonical.Deny},
		{"deny read key.json", readInput("/tmp/service-key.json"), canonical.Deny},

		// Allow cases
		{"allow git status", bashInput("git status"), canonical.Allow},
		{"allow git add", bashInput("git add -A"), canonical.Allow},
		{"allow git commit", bashInput("git commit -m 'test'"), canonical.Allow},
		{"allow git log", bashInput("git log --oneline"), canonical.Allow},
		{"allow git push feature", bashInput("git push origin feature-branch"), canonical.Allow},
		{"allow gh pr list", bashInput("gh pr list"), canonical.Allow},
		{"allow docker build", bashInput("docker build -t app ."), canonical.Allow},
		{"allow go test", bashInput("go test ./..."), canonical.Allow},
		{"allow go build", bashInput("go build ./cmd/..."), canonical.Allow},
		{"allow make", bashInput("make build"), canonical.Allow},
		{"allow pnpm install", bashInput("pnpm install"), canonical.Allow},
		{"allow ls", bashInput("ls -la"), canonical.Allow},
		{"allow find", bashInput("find . -name '*.go'"), canonical.Allow},
		{"allow curl", bashInput("curl https://example.com"), canonical.Allow},
		{"allow openssl", bashInput("openssl rand -hex 32"), canonical.Allow},
		{"allow timeout", bashInput("timeout 120 go test ./..."), canonical.Allow},
		{"allow python", bashInput("python3 -m pytest"), canonical.Allow},
		{"allow pytest", bashInput("pytest -xvs tests/"), canonical.Allow},
		{"allow uv", bashInput("uv pip install requests"), canonical.Allow},
		{"allow cargo", bashInput("cargo build --release"), canonical.Allow},
		{"allow terraform", bashInput("terraform plan"), canonical.Allow},
		{"allow jq", bashInput("jq '.name' package.json"), canonical.Allow},
		{"allow node", bashInput("node server.js"), canonical.Allow},

		// Allow non-Bash tools
		{"allow Read", readInput("/project/src/main.go"), canonical.Allow},
		{"allow Glob", toolInput("Glob"), canonical.Allow},
		{"allow Grep", toolInput("Grep"), canonical.Allow},
		{"allow Edit", toolInput("Edit"), canonical.Allow},
		{"allow Write", toolInput("Write"), canonical.Allow},
		{"allow Agent", toolInput("Agent"), canonical.Allow},

		// Abstain cases (unrecognised commands)
		{"abstain unknown", bashInput("some-exotic-tool --flag"), canonical.Abstain},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := eng.Evaluate(tt.input)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if v.Decision != tt.want {
				t.Errorf("got %s (%s), want %s", v.Decision, v.Reason, tt.want)
			}
		})
	}
}

// TestPreconditionReceivesGatekeeperInput verifies the engine exports the
// tool input to precondition shells as GATEKEEPER_INPUT (required for
// domain-scoped merge checks that parse --repo against the worktree remote).
func TestPreconditionReceivesGatekeeperInput(t *testing.T) {
	// Real executor — do not stub SetExecCommand.
	eng := newEngine(t, []config.Rule{
		{
			Tool:              "Bash",
			Input:             `gh\s+pr\s+merge\b`,
			Precondition:      `printf "%s\n" "$GATEKEEPER_INPUT"`,
			PreconditionMatch: `jim80net/flotilla`,
			Decision:          "deny",
			Reason:            "foreign repo in input",
		},
	})

	v, err := eng.Evaluate(&canonical.ToolCall{
		Tool:        canonical.ToolBash,
		InputString: "gh pr merge 1 --repo jim80net/flotilla",
		CWD:         "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.Decision != canonical.Deny {
		t.Fatalf("want deny when GATEKEEPER_INPUT carries --repo target, got %s reason=%q", v.Decision, v.Reason)
	}

	v2, err := eng.Evaluate(&canonical.ToolCall{
		Tool:        canonical.ToolBash,
		InputString: "gh pr merge 1 --squash",
		CWD:         "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if v2.Decision != canonical.Abstain {
		t.Fatalf("want abstain when no foreign marker in input, got %s", v2.Decision)
	}
}
