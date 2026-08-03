// Package engine evaluates gatekeeper rules against canonical tool calls.
//
// The engine is harness-agnostic: it consumes a canonical.ToolCall and returns
// a canonical.Verdict. All harness-specific wire parsing/encoding lives in the
// adapters (internal/adapter/*); the PCRE2 rule matching, deny-wins policy,
// preconditions, and Bash cd-prefix/heredoc handling live here.
package engine

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/jim80net/gatekeeper-core/canonical"
	"github.com/jim80net/gatekeeper-core/config"
)

// Engine evaluates rules and returns permission decisions.
type Engine struct {
	rules []config.CompiledRule
	debug bool
	// execCommand is overridable for testing preconditions.
	// toolInput is the (heredoc-stripped) tool input string, also exposed to
	// the shell as GATEKEEPER_INPUT so preconditions can inspect the command
	// (e.g. parse --repo against the worktree's authority domain).
	execCommand func(ctx context.Context, cwd, command, toolInput string) (string, error)
}

// SetExecCommand overrides the shell executor (used in tests).
func (e *Engine) SetExecCommand(fn func(ctx context.Context, cwd, command, toolInput string) (string, error)) {
	e.execCommand = fn
}

// New constructs an Engine only from rules admitted and compiled by config.
func New(cfg *config.Config, debug bool) (*Engine, error) {
	rules, err := cfg.CompiledRules()
	if err != nil {
		return nil, err
	}
	return &Engine{rules: rules, debug: debug, execCommand: defaultExecCommand}, nil
}

// Evaluate checks all rules against a canonical tool call and returns a verdict.
// Returns a Verdict with Decision == canonical.Abstain when no rule matches.
func (e *Engine) Evaluate(tc *canonical.ToolCall) (canonical.Verdict, error) {
	inputStr := tc.InputString

	if e.debug {
		canonical.Debugf("evaluate: tool=%s input=%q", tc.Tool, inputStr)
	}

	// For Bash commands with a leading "cd <path> &&", extract the prefix
	// so preconditions run in the correct directory.
	var cdPrefix string
	if tc.Tool == canonical.ToolBash {
		cdPrefix = ExtractCDPrefix(inputStr)
		if e.debug && cdPrefix != "" {
			canonical.Debugf("  extracted cd prefix: %s", cdPrefix)
		}
	}

	// For Bash commands, strip heredoc bodies so deny rules don't match
	// against data content (e.g., commit messages mentioning "rm -rf").
	matchStr := inputStr
	if tc.Tool == canonical.ToolBash {
		matchStr = StripHeredocs(inputStr)
		if e.debug && matchStr != inputStr {
			canonical.Debugf("  stripped heredocs: %q", matchStr)
		}
	}

	var denyReasons []string
	var denyRules []canonical.RuleProvenance
	anyAllow := false
	var allowRules []canonical.RuleProvenance

	for _, rule := range e.rules {
		toolMatch, err := rule.ToolRegex.MatchString(tc.Tool)
		if err != nil || !toolMatch {
			continue
		}

		inputMatch, err := rule.InputRegex.MatchString(matchStr)
		if err != nil || !inputMatch {
			continue
		}

		// Check precondition if present. matchStr (heredoc-stripped for Bash)
		// is exported to the shell as GATEKEEPER_INPUT.
		if rule.PreconditionCmd != "" {
			if !e.checkPrecondition(rule.PreconditionCmd, rule.PreconditionRegex, tc.CWD, cdPrefix, matchStr) {
				if e.debug {
					canonical.Debugf("  precondition failed: %s", rule.Reason)
				}
				continue
			}
		}

		if e.debug {
			canonical.Debugf("  matched: decision=%s reason=%q", rule.Decision, rule.Reason)
		}

		switch rule.Decision {
		case canonical.Deny:
			denyReasons = append(denyReasons, rule.Reason)
			denyRules = append(denyRules, rule.Provenance)
		case canonical.Allow:
			anyAllow = true
			allowRules = append(allowRules, rule.Provenance)
		}
	}

	// Deny always wins.
	if len(denyReasons) > 0 {
		return canonical.Verdict{Decision: canonical.Deny, Reason: strings.Join(denyReasons, "; "), Rules: denyRules}, nil
	}

	if anyAllow {
		return canonical.Verdict{Decision: canonical.Allow, Reason: "Approved by gatekeeper", Rules: allowRules}, nil
	}

	// No match → abstain.
	if e.debug {
		canonical.Debugf("  no rules matched, abstaining")
	}
	return canonical.Verdict{Decision: canonical.Abstain}, nil
}

func (e *Engine) checkPrecondition(cmd string, matchRe *regexp2.Regexp, cwd string, cdPrefix string, toolInput string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// If the Bash command had a leading "cd <path> &&", prepend it to the
	// precondition so it runs in the same directory the command targets.
	effectiveCmd := cmd
	if cdPrefix != "" {
		effectiveCmd = cdPrefix + " " + cmd
	}

	output, err := e.execCommand(ctx, cwd, effectiveCmd, toolInput)
	if err != nil {
		if e.debug {
			canonical.Debugf("  precondition cmd error: %v", err)
		}
		return false
	}

	matched, err := matchRe.MatchString(strings.TrimSpace(output))
	if err != nil {
		return false
	}
	return matched
}

// EnvGatekeeperInput is the environment variable set for every precondition
// shell. Value is the (heredoc-stripped) tool input string under evaluation.
const EnvGatekeeperInput = "GATEKEEPER_INPUT"

func defaultExecCommand(ctx context.Context, cwd, command, toolInput string) (string, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Dir = cwd
	// Always set GATEKEEPER_INPUT (even when empty) so precondition scripts
	// can rely on the variable existing without inventing a second channel.
	cmd.Env = append(os.Environ(), EnvGatekeeperInput+"="+toolInput)
	out, err := cmd.Output()
	return string(out), err
}

// ExtractCDPrefix returns any leading "cd <path> &&" from a Bash command,
// including the "&&". Returns "" if no cd prefix is found.
// This allows preconditions to run in the same directory the command targets.
func ExtractCDPrefix(command string) string {
	idx := strings.Index(command, "&&")
	if idx < 0 {
		return ""
	}
	prefix := strings.TrimSpace(command[:idx])
	if strings.HasPrefix(prefix, "cd ") {
		return strings.TrimSpace(command[:idx+2])
	}
	return ""
}

// heredocStartRe matches heredoc markers: <<EOF, <<'EOF', <<"EOF", <<-EOF, etc.
var heredocStartRe = regexp.MustCompile(`<<-?\s*(?:'(\w+)'|"(\w+)"|(\w+))`)

// shellHeredocRe matches a shell interpreter receiving a heredoc as stdin.
// This detects patterns like: bash <<'EOF', sh <<EOF, python <<'EOF', etc.
// These heredocs contain executable code and must NOT be stripped.
var shellHeredocRe = regexp.MustCompile(`(?:^|[;&|]\s*)(?:bash|sh|dash|zsh|ksh|fish|python[23]?|ruby|perl|node|php)\s+<<`)

// StripHeredocs removes heredoc bodies from a Bash command string.
// This prevents deny rules from matching against data content such as
// commit messages or PR descriptions that happen to contain denied patterns.
// However, heredocs fed as stdin to shell interpreters (bash, sh, python, etc.)
// are preserved because they contain executable code that deny rules must check.
func StripHeredocs(command string) string {
	lines := strings.Split(command, "\n")
	var result []string
	var delim string
	keepBody := false

	for _, line := range lines {
		if delim != "" {
			if keepBody {
				result = append(result, line)
			}
			// Inside a heredoc body — skip/keep lines until closing delimiter.
			if strings.TrimSpace(line) == delim {
				delim = ""
				keepBody = false
			}
			continue
		}

		// Check if this line introduces a heredoc.
		if m := heredocStartRe.FindStringSubmatch(line); m != nil {
			// Capture group 1, 2, or 3 holds the delimiter word.
			for _, g := range m[1:] {
				if g != "" {
					delim = g
					break
				}
			}
			// If a shell interpreter is receiving this heredoc, keep the body.
			if delim != "" && shellHeredocRe.MatchString(line) {
				keepBody = true
			}
		}

		result = append(result, line)
	}

	return strings.Join(result, "\n")
}
