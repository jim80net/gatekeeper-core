# Authorization Domains D1 contract proposal

Status: **proposal; no runtime authority**.

This package makes the approved D1 design executable enough to review and test
without placing credentials, activating PA, or enforcing anything. The source
inputs are pinned in `contract.md`. The Go conformance test deliberately imports
no production Gatekeeper package and reimplements the transition relation from
the fixture documents.

Artifacts:

- `contract.md` — normative semantics and type contracts.
- `action-registry.json` — the complete initial worker action registry (`read`).
- `coverage-manifest.json` — every critical seam and its honest D1-only state.
- `neutral-replay.schema.json` — the implementation-neutral export wire consumed
  by the independent replay checker.
- `fixtures/cases.json` — policy compilation, decision, audit, revoke, and
  lifecycle differential cases.
- `conformance/conformance_test.go` — implementation-independent fixture and
  coverage checker.

Run:

```text
go test ./specs/authorization-domains/v1/conformance
```

Passing this package means only that the proposal is internally consistent. It
does not claim that a final PEP, worker isolation, durable audit, credential
backend, or archive implementation exists.

The neutral replay wire and its closed three-seam coverage registry are aligned
with the independent checker at `1cc451f1ff89aaf8a495b7495a5634ad2609690e`.
That alignment shares only contract data: neither this package nor the checker
imports a production evaluator or canonicalizer.
