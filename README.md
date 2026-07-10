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
