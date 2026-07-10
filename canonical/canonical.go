// Package canonical defines the harness-agnostic core types shared by the
// rule engine and every per-harness adapter.
//
// The gatekeeper evaluates one policy (the TOML rules) across multiple agent
// harnesses (Claude Code, OpenAI Codex, xAI grok). Each harness speaks its own
// hook wire format on stdin/stdout; the adapters translate that wire into the
// canonical types here so the engine never needs to know which harness it is
// serving. Nothing in this package imports a harness-specific package.
package canonical

import (
	"fmt"
	"os"
)

// Decision is the engine's verdict about a single tool call.
//
// Abstain is the load-bearing default: it means "the gatekeeper has no
// opinion — let the harness's native permission system decide." A clean
// no-rule-matched evaluation abstains, and (per the on_error policy default)
// so does any gatekeeper error. Abstain is NOT Allow: an adapter must never
// encode an abstain as an authoritative allow (see internal/adapter).
type Decision int

const (
	// Abstain emits no verdict — the native permission system decides.
	Abstain Decision = iota
	// Allow authorises the tool call.
	Allow
	// Deny blocks the tool call.
	Deny
)

// String renders a Decision for logs and test failures.
func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case Deny:
		return "deny"
	case Abstain:
		return "abstain"
	default:
		return fmt.Sprintf("Decision(%d)", int(d))
	}
}

// Canonical tool names. Every adapter normalises its harness-native tool
// taxonomy onto these, so one ruleset ("tool = 'Bash'", ...) applies to all
// harnesses. Unknown/MCP tools pass through under their own name.
const (
	ToolBash      = "Bash"
	ToolRead      = "Read"
	ToolWrite     = "Write"
	ToolEdit      = "Edit"
	ToolGlob      = "Glob"
	ToolGrep      = "Grep"
	ToolWebFetch  = "WebFetch"
	ToolWebSearch = "WebSearch"
	ToolAgent     = "Agent"
)

// ToolCall is the harness-neutral representation of a tool invocation, produced
// by an adapter's ParseInput and consumed by the engine's Evaluate.
type ToolCall struct {
	// Tool is the canonical tool name (see the Tool* constants), already
	// mapped from the harness-native name by the adapter.
	Tool string
	// InputString is the primary matchable string for the tool: the shell
	// command for Bash, the file path for Read/Write/Edit, the pattern for
	// Glob/Grep, etc. The adapter extracts this from the harness stdin.
	InputString string
	// CWD is the working directory the tool call runs in (used to locate the
	// project config overlay and to run rule preconditions).
	CWD string
	// PermissionMode is the harness's current permission mode, carried for
	// context/logging. The engine does not branch on it.
	PermissionMode string
	// EventName is the hook event name (e.g. "PreToolUse"); may be empty.
	EventName string
}

// Verdict is what the engine emits and an adapter encodes: a decision plus a
// human-readable reason.
type Verdict struct {
	Decision Decision
	Reason   string
}

// DebugEnabled controls whether Debugf writes to stderr.
var DebugEnabled bool

// Debugf writes debug output to stderr when DebugEnabled is true. It lives in
// the canonical core so the engine, config, and adapters can all log without
// depending on any harness-specific package.
func Debugf(format string, args ...interface{}) {
	if DebugEnabled {
		fmt.Fprintf(os.Stderr, "[gatekeeper] "+format+"\n", args...)
	}
}
