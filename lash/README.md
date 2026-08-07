# Gatekeeper Lash prototype

Status: source-only prototype; **not an enforcement boundary and not a Bash replacement**.

This package begins with acceptance proof 3: bind a deterministic Gatekeeper
authorization to the exact execution artifact and reconstructed environment so
that check/use substitution cannot turn an authorized plan into a different
effect.

## Implemented in this slice

- deterministic canonical execution plan containing the absolute executable,
  executable SHA-256, argv, cwd, sorted explicit environment, UID/GID, sandbox
  profile, and logical (never physical) credential identifiers;
- Ed25519 signature over the deterministic authorization and plan digest;
- verification of signature, authorization lifetime, and exact plan digest;
- verified executable bytes held by an open file description so the eventual
  Linux executor can use that same object with `execveat(..., AT_EMPTY_PATH)`;
- advisory classifier results that cannot loosen deterministic denial;
- per-scope/window limits on classifier-created denial or human-review blocks,
  with an observation for every result and deterministic-allow fallback under
  sustained disagreement;
- pre-call token/call/spend reservation. The prototype configuration has a
  zero-spend ceiling, so any nonzero provider-cost estimate is rejected before
  a request can be made.

## What this does not claim

There is no executor, DomainContext minter, durable audit writer, replay store,
credential broker, Landlock/bubblewrap profile, classifier client, or SIEM
export in this slice. `OpenBoundArtifact` proves the file-description handoff
shape, but proof 3 is not complete until a Linux executor verifies a binding
and calls `execveat` on that same descriptor while applying the exact bound
environment and sandbox identity. Reopening the path is forbidden. An open
descriptor defeats rename/path replacement but does not prevent an authorized
inode from being modified in place; the executor must use a sealed snapshot
(for example, a sealed `memfd`) or require an independently proven immutable
artifact before proof 3 is complete.

Classifier fallback does not override static policy: it returns to an existing
deterministic allow only after advisory disagreement crosses the configured
availability threshold. Deterministic denies always remain denies. The
observation sink must become durable before classifier narrowing can leave
shadow mode.

## Classifier cost envelope

No API call is made by this prototype. Before enabling one, shadow telemetry
must measure:

`monthly cost = seats × shell calls/seat/day × 30 × trigger rate × cost/call`

Illustrative—not measured—fleet envelope:

- 53 seats;
- 500 shell calls per active seat per day;
- 300 input and 30 output tokens per ambiguous classification.

At published standard prices on 2026-08-07:

| Model | Input/output per 1M | Cost per classified call | 1% trigger | 10% trigger | 100% trigger |
| --- | ---: | ---: | ---: | ---: | ---: |
| GPT-5 nano | $0.05 / $0.40 | $0.000027 | $0.21/mo | $2.15/mo | $21.47/mo |
| GPT-5.4 nano | $0.20 / $1.25 | $0.0000975 | $0.78/mo | $7.75/mo | $77.51/mo |

Source: <https://developers.openai.com/api/docs/models/gpt-5-nano> and
<https://developers.openai.com/api/docs/models/gpt-5.4-nano>.

Those totals scale linearly with calls, tokens, and active seats. The numbers
are not a spend request: they show why all-command classification is rejected
and why the existing invocation-design shadow window must measure the ambiguous
trigger rate first. A local model still has compute/operations cost, but no
provider charge; it remains subject to the same call/token caps and quality
gates. Any nonzero API budget or dedicated local hardware returns as the
required nine-field spend brief.

## Next acceptance step

Implement the Linux-only descriptor executor behind a build tag, first with a
test helper artifact and an empty reconstructed environment. The mutation test
must replace the executable path after verification and prove that only the
already-open authorized file description can run. Add durable-before-effect
audit admission before permitting protected effects.
