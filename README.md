# gatekeeper-core

Shared **permission-gate** engine for coding agents: load `gatekeeper.toml`,
PCRE2 rule evaluation, deny-wins, harness-neutral tool taxonomy.

**Memex-core analog** for constraints. Adapters (`gatekeeper-claude`,
`gatekeeper-grok`, `gatekeeper-codex`) wrap this substrate; they only change
hook wire format, not the rule language.

## Module

```
github.com/jim80net/gatekeeper-core
  /canonical   Decision, ToolCall, Verdict, tool names
  /config      TOML load, layering, on_error
  /engine      PCRE2 Evaluate, GATEKEEPER_INPUT preconditions
```

```bash
go get github.com/jim80net/gatekeeper-core@latest
```

## Policy

One `gatekeeper.toml` across harnesses. Deny always wins.

### Invocation-aware Bash rules

Bash deny rules can bind their regex to a parsed command identity:

```toml
[[rules]]
tool = 'Bash'
executables = ['git']
subcommand = 'reset'
input = 'git\s+reset\s+--hard'
decision = 'deny'
reason = 'Destructive: git reset --hard'
```

`executables` matches exact executable basenames. `subcommand` matches an exact
token (including after supported Git global options), so `git merge` is distinct
from `git merge-base`. The input regex is evaluated only against normalized
literal words from a matching invocation; the original byte span is retained as
provenance. Quoted data in another command cannot manufacture an invocation.
Rules without `executables` retain legacy whole-input matching for compatibility
and should not be used for new Bash deny policy.

The closed literal-wrapper set currently unwraps `env`, `command`, `nice`, `nohup`,
and `timeout`. Interpreter and executor handoffs not yet resolved by that set retain
their legacy verdict during the staged rollout and carry no `ShellMatches`
entry; consumers must not restate those decisions as parsed-operation proof.

Verdicts from structured rules include the invocation ID, exact executable and
subcommand, byte span, source digest, and parser version. Decision records and
replay comparisons should persist those fields: a raw command plus a verdict is
no longer sufficient to prove which operation fired. Parser-version changes are
new replay generations, not byte-compatible substitutions.

Executable heredocs retain the separately named conservative policy
`P0 interim: heredoc blocked pending preserve-unless-proved-data classification`.
That P0 intentionally carries no parsed-invocation claim and is not evidence
that the heredoc body was resolved by ShellPlan.

## Status

Phase 1a extract from the historical monorepo (`gatekeeper-claude` /
`internal/{canonical,config,engine}`). Binary install path remains
`claude-gatekeeper` in the Claude adapter repo until a later rename.

## Namespace

Repos under **`jim80net` only** (operator standing rule).

## Tests

```bash
go test -race -count=1 ./...
```
