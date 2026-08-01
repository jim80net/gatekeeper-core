# D1 executable contract: open-by-default protected resources

## Authority and boundary

Normative source inputs:

- Design GO: `state/decisions/2026-08-01-auth-domains-design-go.md`.
- Authorization Domains r2 SHA-256
  `557c226f4e253e951affafe165ebfea0955389dfce9bd0f787d9da1a121e4fca`.
- Block Buzz analysis SHA-256
  `cf049f5ca36e7c5ecb3c6d246b8267c730be71eaa887acdc5d4264a528947299`.

This chapter specifies contracts only. It creates no credential binding, PA
activation, runtime enforcement, deployment, off-host sink, or paid service.

Normative terms use MUST, MUST NOT, SHOULD, and MAY in their usual RFC 2119
sense. Unknown fields in every signed or persisted D1 document MUST reject the
whole document.

## 1. Exact first object and action registry

The first protected object is exactly:

```text
object_id: credential://pa/google-service-account-keyfile/v1
object_class: service_account_keyfile
selector_kind: exact
```

The URI is a stable logical object identity, not a filesystem locator and not
credential material. Its physical backend/path binding is deliberately absent
from D1 and MUST remain unresolved until separately reviewed implementation work.
No wildcard, provider namespace, sibling file, or alternate credential is
included.

The complete initial worker action registry is `read`: observe or materialize
bytes from the exact protected object. Policy administration and lifecycle
operations are control-plane transitions, not worker actions. Adding any worker
action requires a new design review and registry version.

## 2. Immutable policy generation

```text
PolicyGeneration {
  schema_version: "authorization-domains/v1"
  generation: uint64 (> 0)
  parent_digest: sha256 | null
  digest: sha256(canonical document excluding digest)
  registry_version: "1"
  blocks: ProtectedBlock[]
  exceptions: BlockException[]
  created_at: RFC3339
}

ProtectedBlock {
  id: stable non-empty string
  object_selector: { kind: "exact", object_id }
  actions: non-empty subset of registry
  reason, owner: non-empty string
  audit_policy: "durable_before_effect"
  created_at: RFC3339
  expires_at?: RFC3339
}

BlockException {
  id, block_id: stable non-empty string
  principal_id, worker_id: exact authenticated identities
  actions: non-empty subset of matching block actions
  object_selector: exact and equal to the block in v1
  domain_id: exact server-resolved domain
  session_id: exact authenticated session
  issued_by, issued_at, expires_at: required
  lease: { not_after, max_materializations: 1 }
}
```

Candidate compilation MUST reject unknown fields/actions/registry versions,
duplicate IDs, dangling exceptions, wider exception scope, expired blocks at
publish time, equal-specificity overlap ambiguity, non-canonical objects, and
invalid timestamps. File order never resolves authority.

Publish is an atomic, idempotent expected-generation compare-and-swap:

```text
publish(candidate, expected_generation, idempotency_key)
```

- An already successful idempotency key with the same digest returns the prior
  result; reuse with another digest rejects.
- `expected_generation` MUST equal current last-good or publish rejects.
- A rejected candidate never changes last-good.
- A successful publish creates one immutable successor; generations never
  mutate or roll back in place.
- Recovery loads the newest fully admitted valid generation; corruption or a
  missing successor retains last-good and blocks only named protected effects.

## 3. Identity and server-minted DomainContext

Workers and sessions are authenticated server-side. Model text, environment
variables, tool arguments, and caller-provided domain selectors are untrusted
claims only.

```text
DomainContext {
  schema_version: "authorization-domains/v1"
  context_id: unique server-minted ID
  domain_id: server-resolved authority domain
  principal_id, worker_id, session_id: authenticated bindings
  runtime_identity: { kind: "linux_user" | "container", subject }
  isolation_claim: "unproved" | "proved_linux_user" | "proved_container"
  issued_at, expires_at: RFC3339
  mint_authority: server component identity
  claimed_domain_id?: untrusted evidence only
}
```

Every protected PEP, policy store, replay, audit, and lifecycle API MUST accept
the complete server-minted `DomainContext`, never a naked domain ID. It MUST
reject expired contexts or identity/session substitutions. Claimed and resolved
context remain distinct in evidence.

## 4. Normative request and decision

```text
AuthzRequest {
  schema_version, request_id
  domain_context: DomainContext
  action
  object: { object_id, canonicalization_version }
  policy_generation
  classifier_version
  requested_at
}

AuthzDecision {
  schema_version, request_id
  decision: permit_unblocked | permit_exception | deny_blocked
  reason_code
  policy_generation
  block_ids[]
  exception_id?: string
  evaluated_constraints
  lease_not_after?: RFC3339
  decision_id, decided_at
}
```

Evaluation is deterministic:

1. If no protected block matches the canonical object/action, return
   `permit_unblocked`; unknown ordinary actions remain open.
2. Once an object is protected, unknown action, stale generation, invalid or
   expired context/session, ambiguity, or unavailable policy returns
   `deny_blocked`.
3. Matching blocks deny unless one exact, unexpired exception covers every
   matching block and binds the resolved domain, authenticated principal,
   worker, session, object, and action.
4. An exact exception returns `permit_exception` only inside its constraints
   and lease. It cannot erase another applicable block.

The evaluator returns no physical path, credential bytes, token, or provider
secret. A decision is not itself materialization authority.

## 5. Durable admission, replay, and final PEP

Before a protected permit crosses a final PEP, the local authoritative audit
writer MUST durably admit the request and decision and the replay store MUST
atomically claim `(decision_id, pep_id, materialization_ordinal)`. Audit or
replay unavailability stops only the named protected effect. Ordinary unblocked
work remains open.

The PEP consumes an opaque binding scoped to the exact decision, object, action,
domain context, session, PEP, generation, and short expiry. It MUST reject stale,
replayed, mismatched, or unaudited bindings and MUST NOT reinterpret policy.

`coverage-manifest.json` is normative. A protection claim is forbidden unless
every direct protocol/backend path for the object has a named final PEP, owner,
negative bypass fixture, trace action, and `implemented_and_probed` state. D1
lists all known seams as `contract_only`; therefore this proposal makes no
enforcement claim. Unknown or untraced critical seams fail coverage.

## 6. Audit, revoke, and last-good behavior

Audit events are append-only and correlated by request, decision, context,
generation, PEP, worker/session, block/exception, and outcome IDs. The local
writer assigns a monotonic per-domain sequence and previous-entry hash. Unknown
event schemas/actions fail verification. Audit payloads MUST NOT contain raw
commands, physical credential locators, credential bytes, tokens, headers,
sensitive URL queries, email bodies, or protected archive content.

Revocation publishes a successor generation through CAS, invalidates affected
contexts/sessions and replay bindings, stops new final-PEP materialization, and
emits propagation acknowledgements. A cache MUST NOT reuse a protected permit
older than the applicable block or exception revision. Already-materialized
bytes are reported honestly; revoke cannot make them unknown.

## 7. Lifecycle, isolation, preserve, and archive

The lifecycle state machine is:

```text
provision -> operate -> preserve -> archive
```

Lifecycle mechanics MUST bound queues, concurrency, timeouts, restarts, and
process-tree cleanup; child environments are cleared and reconstructed from a
minimal non-secret allowlist. These mechanics never earn an isolation claim.
Only recorded cross-worker probes under a dedicated Linux UID or constrained
container may set a proved isolation value. Shared UID and process groups remain
`unproved`.

Archive is a revoke drill. Its immutable receipt records worker/session stop,
successor generation, exception removal, absence of protected mounts/material
from the bundle, artifact custody/retention, useful-artifact readability, known
residuals, and any failed step. A partial receipt cannot claim completion.

## 8. Independent conformance and differential fixtures

The conformance checker MUST import no production evaluator, canonicalizer,
policy store, or PEP package. It reimplements this transition relation from
fixture data. Traces preserve claimed and resolved context separately. Missing
or unknown critical trace actions are coverage failures.

Fixtures cover at minimum: ordinary open work; exact block denial; exact
exception permit; wrong worker/session/domain; unknown protected action; stale
generation; expired exception/context; ambiguous generation rejection; CAS and
idempotency; audit/replay unavailable; direct-path and symlink bypass; revoke;
archive completeness; and lifecycle mechanics that do not overclaim isolation.

Differential execution against a future production implementation is an I1a
gate. D1 fixture success alone is not runtime proof.

### 8.1 Neutral replay export

Independent differential runners exchange `gatekeeper.auth-domains.replay/v1`
documents described by `neutral-replay.schema.json`. The export has exactly
three closed coverage seams:

| seam | critical | contract mapping |
| --- | --- | --- |
| `ordinary-work` | no | ordinary open-by-default work |
| `protected-read-pep` | yes | evaluator, replay claim, and final PEP |
| `protected-read-audit` | yes | durable audit admission |

Every critical seam MUST be present and traced. Records on unknown seams,
unknown critical seams, and missing or untraced critical seams fail replay
conformance. The broader implementation inventory remains normative for a
future enforcement claim; this closed export registry is only its neutral
differential projection.

Each record keeps `claimed_context` and `resolved_context` distinct. A
protected record MUST bind its decision to the server-resolved context ID and
identify `server_resolved` as its context source; caller claims never grant
authority. The independent checker uses the inert synthetic object
`fixture://authorization-domains/protected/exact-read-object`, not the PA
object ID or any physical credential locator. Its current decision projection
covers ordinary `allow/unprotected` and protected `deny/protected_block`.

Lifecycle probe receipts carry `probe_id`, trace and expected/actual result,
reason code, runtime generation, specification and evidence digests, audit
outcome ID, duration, post-probe claim, receipt outcome, signer ID, and
signature. An absent, failed, or unverifiable isolation probe suppresses a
proved isolation claim; lifecycle mechanics alone never establish isolation.
