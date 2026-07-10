# gatekeeper-core

Shared **permission-gate** engine for coding agents: load `gatekeeper.toml`,
PCRE2 rule evaluation, deny-wins, harness-neutral tool taxonomy.

This is the **Memex-core analog** for constraints. Harness adapters
(`gatekeeper-claude`, `gatekeeper-grok`, `gatekeeper-codex`) wrap this
substrate.

**Status:** flotilla stand-up 2026-07-10. Implementation still lives in
[`gatekeeper-claude`](https://github.com/jim80net/gatekeeper-claude)
(`internal/{canonical,config,engine}`). Extraction is **Phase 1** of the
XO extract plan — see private
[`gatekeeper-flotilla/docs/EXTRACT-PLAN.md`](https://github.com/jim80net/gatekeeper-flotilla)
(and fleet copy under a1-fleet-ops backlog-detail if mirrored).

## Policy

One `gatekeeper.toml` across harnesses — adapters only change the hook wire
format, not the rule language.

## Target module (after Phase 1)

```
github.com/jim80net/gatekeeper-core
  /canonical
  /config
  /engine
```

Do not invent a second evaluation path. Until extract merges, depend on
`gatekeeper-claude` for runnable binary and tests.
