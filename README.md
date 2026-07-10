# gatekeeper-core

Shared **permission-gate** engine for coding agents: load `gatekeeper.toml`,
PCRE2 rule evaluation, deny-wins, harness-neutral tool taxonomy.

This is the **Memex-core analog** for constraints. Harness adapters
(`gatekeeper-claude`, `gatekeeper-grok`, `gatekeeper-codex`) wrap this
substrate.

**Status:** flotilla stand-up 2026-07-10. Implementation initially lives in the
historical monorepo (`claude-gatekeeper` / `gatekeeper-claude`); extraction into
this package is the core desk's first product cut.

## Policy

One `gatekeeper.toml` across harnesses — adapters only change the hook wire
format, not the rule language.
