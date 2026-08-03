# D1 delta: fleet permission map for credentialed entryways

Status: **design proposal; no runtime authority**.

This delta is normative design text against `contract.md` as ratified at
`723b4f05647e577069c15b261bd214d9c21241e6`. It is authorized by the operator
requirement recorded in
`state/decisions/2026-08-03-auth-domains-fleet-permission-map-requirement.md`.
It creates no credential binding, physical locator, implementation, deployment,
or paid service. The existing D1 lifecycle, audit, replay, and last-good rules
continue to apply unless this delta explicitly narrows them.

Normative terms use MUST, MUST NOT, SHOULD, and MAY in their usual RFC 2119
sense. Unknown fields in signed or persisted documents MUST reject the whole
document.

## 1. Closed selector and action registries

This delta advances the registry version from `"1"` to `"2"`. A version-2
policy or permission map MUST bind the digest of the exact admitted registry
generation. Adding or changing a selector class, class member, action, or
action meaning requires design review, a registry successor, and a registry
version change. File order and string resemblance never confer membership.

### 1.1 Capability-class selector

Version 2 adds `class` beside `exact`:

```text
ObjectSelector =
  { kind: "exact", object_id: LogicalObjectID }
| { kind: "class", class_id: CapabilityClassID }

CapabilityClass {
  class_id: stable non-empty string
  purpose: non-empty string
  members: sorted unique LogicalEntrywayID[]
}
```

A capability class is a closed, reviewed set of exact logical entryway IDs in
one immutable registry generation. A class selector matches an entryway if and
only if its exact logical ID appears in `members`. It MUST NOT infer membership
from URI prefixes, provider names, labels, paths, regular expressions, glob
syntax, roster hierarchy, nested classes, or future registry additions. A
member added in a successor registry does not retroactively widen a decision
or binding made against an older registry digest.

The registry MUST define `credentialed-entryway` as the class of final PEPs
that either materialize credential material or mediate credential-backed or
search-network egress. Provider- or capability-specific classes such as
`web-search`, `x`, and `google` MAY partition or overlap that closed membership,
but they are not provider namespace wildcards. Every member remains an exact
logical entryway ID. A new or unclassified candidate entryway is not a member
by naming convention and MUST NOT operate until an admitted registry successor
classifies it.

Logical entryway and object IDs are stable identifiers only. They MUST NOT
contain or resolve to a credential, filesystem path, physical backend locator,
secret-bearing endpoint, token, or provider account identifier.

### 1.2 Worker action registry

The complete version-2 worker action registry is:

| action | normative effect |
| --- | --- |
| `read` | Observe or materialize bytes from an exact protected object. |
| `network_egress` | Cause a network request and receive its result through a mediated entryway without exposing credential material to the worker. |
| `credentialed_effect` | Cause an external state-changing operation through a mediated entryway using credential authority that remains behind the final PEP. |

These action names are exact and closed. `network_egress` does not imply
`credentialed_effect`; `credentialed_effect` does not authorize raw `read`;
and no action implies another. Policy administration, registry publication,
granting, revocation, and lifecycle transitions remain control-plane actions,
not worker actions. Adding the next worker action requires the same design
review and version change as this delta.

## 2. Immutable fleet permission map

The permission map is its own generation-chained policy artifact. It references
stable seat identities owned by the fleet roster, but MUST NOT be stored in,
derived from, or rewritten with that mutable operational roster.

```text
FleetPermissionMap {
  schema_version: "authorization-domains/fleet-permission-map/v1"
  map_id: stable non-empty string
  generation: uint64 (> 0)
  parent_digest: sha256 | null
  digest: sha256(canonical document excluding digest)
  registry_version: "2"
  registry_digest: sha256
  posture: {
    ordinary_work: "open"
    credentialed_entryway: "deny_unless_active_exact_seat_grant"
  }
  grants: StandingSeatGrant[]
  revocations: GrantRevocation[]
  issued_by: authenticated authority identity
  created_at: RFC3339
}

StandingSeatGrant {
  grant_id: stable non-empty string
  seat_id: exact stable roster-owned seat identity
  entryway_selector: ObjectSelector
  actions: non-empty subset of the version-2 worker action registry
  granted_by: authenticated authority identity
  granted_at: RFC3339
  not_before: RFC3339
  expires_at: RFC3339
  reason: non-empty string
}

GrantRevocation {
  revocation_id, grant_id: stable non-empty strings
  revoked_by: authenticated authority identity
  revoked_at: RFC3339
  reason: non-empty string
}
```

`entryway_selector` MAY be one exact logical entryway or one closed capability
class. It MUST NOT name a seat subtree, role, harness, parent, display name,
provider namespace, wildcard, or computed group. Every grant binds exactly one
stable seat ID. A seat rename, harness switch, display-name change, or parent
change MUST NOT change that ID or redirect a grant. Deleting and recreating a
seat MUST produce a new ID; the old grant MUST NOT follow it.

The map uses the immutable-generation, digest, expected-generation CAS,
idempotency, validation, recovery, and last-good behavior of `PolicyGeneration`.
A candidate additionally rejects duplicate grant/revocation IDs, dangling or
duplicate revocations, unknown seats, selectors or actions, invalid registry
bindings, non-canonical ordering, invalid time windows, and a grant selector
that includes a non-entryway object. An invalid candidate never replaces the
last-good map.

A standing grant is active only when its exact seat, selector, action,
registry digest, map generation, and time window match the server-resolved
request and no admitted revocation names it. Revocation publishes an immutable
successor, stops new decisions at the final PEP, closes associated leases, and
reports already-completed external effects honestly.

### 2.1 Standing grants do not replace exceptions

A `StandingSeatGrant` permits repeated, mediated use of an entryway action. It
is not a bearer credential, is not copied into worker input, and never exposes
credential bytes or a physical locator. Each use still requires a fresh
server-resolved decision, durable audit admission, replay protection, and final
PEP enforcement against the current map generation.

A `BlockException` remains an exact principal/worker/session authorization with
`max_materializations: 1`. It cannot create standing authority. Conversely, a
standing grant cannot erase a `ProtectedBlock` or authorize raw credential
materialization: `read` of a protected object still requires the matching exact
`BlockException` in addition to any entryway grant. The two records have
separate IDs, lifecycles, revocation, and audit evidence.

## 3. Scoped posture inversion

Ordinary work remains open by default exactly as D1 specifies. This delta MUST
NOT be interpreted as fleet-wide default-deny.

Only an operation crossing a registered member of `credentialed-entryway` is
deny-by-default. Such an operation returns deny unless an active grant binds
the exact server-resolved seat, entryway or closed class, and action. There are
no implicit grants for research desks, roles, roster parents, labels, or other
groups; therefore every seat, including every research seat, is sandboxed from
credentialed entryways until granted individually.

An unavailable, corrupt, stale, ambiguous, or unknown permission-map or
registry generation; an unknown or unclassified entryway; an unknown action;
or a missing stable seat identity MUST deny the named entryway effect. That
failure MUST NOT deny unrelated ordinary work. An implementation MUST NOT
classify an entryway as ordinary merely because classification failed.

## 4. Normative entryway request and decision

The existing `AuthzRequest` and `AuthzDecision` are extended, not replaced:

```text
EntrywayAuthzRequest {
  schema_version, request_id
  domain_context: DomainContext
  seat_id: exact server-resolved stable seat identity
  action: version-2 worker action
  entryway: { entryway_id, registry_digest }
  object?: { object_id, canonicalization_version }
  policy_generation
  permission_map_generation
  requested_at
}

EntrywayAuthzDecision {
  schema_version, request_id
  decision: permit_standing_grant | deny_entryway
  reason_code
  policy_generation
  permission_map_generation
  registry_digest
  entryway_id, action, seat_id
  grant_id?: string
  evaluated_constraints
  lease_not_after: RFC3339
  decision_id, decided_at
}
```

The trusted ingress obtains `seat_id` from authenticated server-side fleet
identity resolution. Model text, prompts, environment variables, roster display
names, tool arguments, and caller-provided seat or class claims are untrusted
evidence and MUST NOT select authority. The decision binds the exact resolved
seat and current map generation; a decision is not itself entryway authority.

Evaluation is deterministic:

1. If the PEP is not a registered `credentialed-entryway` member, this delta
   does not change D1 ordinary-work evaluation.
2. A registered member denies unless one active exact-seat grant covers its
   exact entryway (directly or by closed class membership) and action.
3. Multiple matching grants do not widen one another. Each is independently
   valid; the decision records a deterministic grant ID selected by canonical
   ordering and audits all matching IDs.
4. Any unknown, stale, invalid, revoked, expired, or ambiguous input returns
   `deny_entryway`. A deny cannot be converted to ordinary open work.
5. If the effect also reads a protected object, both this decision and the
   existing protected-object decision MUST permit before the final PEP acts.

## 5. Final-PEP boundary

The controlling PEP is the last trusted component at which credential material
would be materialized or credential-backed/search network egress or an external
effect would occur. It MUST enforce the server-resolved seat, exact entryway,
action, registry digest, current permission-map generation, active grant,
decision binding, durable-before-effect audit, and replay/lease constraints.
Unavailable audit, replay, registry, map, or final-PEP state denies only the
named credentialed-entryway effect.

Tool names, command strings, argument patterns, input regular expressions, and
prompt classifiers MAY provide defense in depth but MUST NOT be the controlling
boundary or satisfy final-PEP coverage. Against prompt injection the agent is
adversarial with respect to spelling and routing; therefore name matching
cannot prove that credential material or egress remained controlled.

Coverage manifests MUST identify every materialization, network, provider SDK,
browser, proxy, helper, and direct backend path capable of the registered
effect. A protection claim is forbidden until every critical path has an owned
final PEP and independently exercised negative bypass evidence.

## 6. Operator-inspectable projection

The authoritative map remains the signed immutable artifact. A dashboard MAY
consume only this read-only projection, produced by a trusted reader of an
admitted map and registry generation:

```text
FleetPermissionMapProjection {
  schema_version: "authorization-domains/fleet-permission-map-projection/v1"
  map_id, generation, digest, parent_digest
  registry_version, registry_digest
  generated_at: RFC3339
  posture: {
    ordinary_work: "open"
    credentialed_entryway: "deny_unless_active_exact_seat_grant"
  }
  entryways: [{
    entryway_id: stable logical ID
    classes: sorted CapabilityClassID[]
    supported_actions: sorted worker action[]
    authorized_seats: [{
      seat_id: exact stable roster-owned identity
      grant_id
      actions: sorted worker action[]
      granted_by: authenticated authority identity
      granted_at, not_before, expires_at: RFC3339
      status: "scheduled" | "active" | "expired" | "revoked"
      revoked_by?: authenticated authority identity
      revoked_at?: RFC3339
    }]
  }]
}
```

The projection MUST be reproducible from the named map and registry digests,
must retain expired and revoked records needed to explain authority history,
and MUST fail closed rather than render a partial map as current. The dashboard
resolves human-readable seat labels from the roster as non-authoritative
display data; labels, harnesses, and parentage MUST NOT be persisted as grant
keys or used to join authority.

The projection MUST NOT expose credential material, object material, physical
locators, filesystem paths, provider account identifiers, tokens, headers,
secret-bearing endpoints, or backend bindings. Logical entryway/class IDs,
stable seat IDs, grant metadata, generation/digest data, and non-secret reason
codes are the complete security projection.

## 7. Conformance obligations

No gate result is evidence until the gate has been observed failing for the
specific defect it exists to catch. Future conformance work for this delta MUST
use an independent oracle and include, at minimum, negative controls for an
unauthorized exact seat, a revoked-grant use, an expired grant, a caller-claimed
seat substitution, an unknown entryway, an entryway removed from a successor
registry, a stale map generation, and a bypass around each final PEP. At least
one planted unauthorized grant and one planted revoked-grant attempt MUST fail
before the corresponding positive evidence can support a gate.

Production evaluator, classifier, canonicalizer, registry, projection, or PEP
code MUST NOT be imported or restated by the oracle that judges it. This design
adds no fixtures and makes no conformance or enforcement claim.

## 8. Questions requiring operator resolution before ratification

1. **Granting authority:** Which authenticated identities or roles may issue and
   revoke a standing seat grant, and may any authority delegate that power?
   `granted_by`, `revoked_by`, and map `issued_by` are recorded above, but the
   admission allowlist cannot be specified without this decision.
2. **Maximum lifetime:** Must every standing grant have a finite operator-set
   maximum duration, and if so what is it? This draft requires a finite
   `expires_at` but does not invent a duration or renewal rule.
