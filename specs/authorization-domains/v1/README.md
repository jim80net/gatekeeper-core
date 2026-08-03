# Authorization Domains D1 contract proposal

Status: **proposal; no runtime authority**.

This package makes the approved D1 design executable enough to review and test
without placing credentials, activating PA, or enforcing anything. The source
inputs are pinned in `contract.md`. The Go conformance test deliberately imports
no production Gatekeeper package and reimplements the transition relation from
the fixture documents.

Artifacts:

- `contract.md` — normative semantics and type contracts.
- `fleet-permission-map-delta.md` — design proposal for closed capability
  classes, exact-seat standing grants, scoped entryway denial, and its
  operator-inspectable projection.
- `action-registry.json` — the complete initial worker action registry (`read`).
- `coverage-manifest.json` — every critical seam and its honest D1-only state.
- `domain-context-cases.json` — server-mint, override rejection, and same-principal
  cross-community key-separation cases.
- `neutral-replay.schema.json` — the implementation-neutral export wire consumed
  by the independent replay checker.
- `lifecycle-probes.json` — the pinned lifecycle/isolation claims, invalidators,
  and complete synthetic probe registry.
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
with the independent checker at `8e376c79d64bc720b280ab839058cc71ca774990`.
That alignment shares only contract data: neither this package nor the checker
imports a production evaluator or canonicalizer.
