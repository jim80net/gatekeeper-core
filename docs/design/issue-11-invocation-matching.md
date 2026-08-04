# Issue #11 design: match shell invocations, not mentions

Status: **design proposal; no implementation authority**.

## Evidence subject and invariant

This analysis was generated against `gatekeeper-core` `main` at exact ref
`4c92738cb9e6dbb5ed5db139f9386e39adadef02`. At that ref, `ToolCall` exposes a
single Bash `InputString`, `Engine.Evaluate` applies each rule regex to that
string after `StripHeredocs`, and the shipped policy mixes executable identity
and argument predicates inside whole-command regexes. No runtime behavior was
probed for this note.

The live reproduction in issue #11 names deployed fleet binary **1.5.1** as its
subject. Main is ahead of that deployed binary; the issue evidence must not be
read as a probe of this design branch or current main.

The governing invariant is the fleet doctrine “identify by identity, never by
mention” (origin `469022e0`). For a Bash tool call, the identity is a shell
invocation in command position plus its arguments and execution context. Text
inside another invocation's data argument is not that identity.

No static pre-execution representation fully closes this class. Shells compute
commands through expansion, functions, aliases, sourced code, substitutions,
and interpreters. The honest target is therefore:

1. eliminate mention matches for statically identifiable invocations;
2. preserve every shipped denial for statically identifiable real invocations;
3. fail closed on executable constructs whose identity cannot be established
   without running attacker-controlled code; and
4. name every unsupported or opaque construct as residual evidence rather than
   treating it as ordinary safe text.

## Alternatives

### A. Shell-aware tokenization and command-position matching

Parse the Bash input without executing it and walk the shell AST. Produce one
invocation record per simple command, including commands in pipelines,
subshells, command substitutions, and both sides of `;`, `&&`, and `||`.
Separate the executable word from argument words. Evaluate a rule only against
an invocation whose executable identity matches that rule; do not scan data
arguments belonging to `echo`, `printf`, HTTP clients, or other unrelated
commands for a second command's identity.

This fixes quoted examples, JSON, `echo`, and `--flag=value` mentions when they
are ordinary arguments. It also handles literal multi-command lines and
literal command substitutions because those are distinct AST nodes.

False-negative and evasion risks:

- A tokenizer alone does not perform shell expansion. `$cmd --hard`,
  `${tool} ...`, aliases, functions, sourced files, and constructed option
  strings may hide executable or argument identity.
- Literal `eval 'rm -rf /'` and `sh -c 'git reset --hard'` require recursive
  parsing with wrapper-specific semantics. Dynamic `eval "$payload"` and
  `sh -c "$payload"` cannot be resolved statically.
- `base64 -d | sh`, generated scripts, `xargs`, `find -exec`, and interpreter
  APIs can move the invocation across a process boundary or encode it.
- Redirections, globbing, brace expansion, process substitution, and shell
  parameter operators can change arguments after parsing.
- A generic token list is insufficient for wrappers such as `env`, `command`,
  `sudo`, `timeout`, and nested shells; each needs an admitted unwrapping rule.

These risks are acceptable only if unresolved executable identity is a distinct
fail-closed result, not “no deny rule matched.” A parser error, unsupported
wrapper, dynamic command word, dynamic interpreter body, or opaque executable
handoff MUST deny or return a gate error governed by an explicitly fail-closed
posture. Under the shipped `on_error = "abstain"`, merely returning an error is
not fail closed, so the implementation design must add a policy-level dynamic-
execution denial rather than rely on `on_error`.

### B. Extend strip-before-match to quoted strings

Generalize `StripHeredocs` by deleting or masking single-quoted and
double-quoted text before applying the existing whole-command regexes.

This fixes some mentions cheaply: `echo 'rm -rf /'`, a quoted JSON payload, or
a quoted `--note=...` value no longer looks like an invocation to the regex.

It introduces unacceptable false negatives:

- Quotes are shell syntax, not a data classification. `rm '-rf' '/'`,
  `git reset '--hard'`, `git push '--force'`, and
  `git branch '--delete' '--force' topic` are real destructive invocations.
  Stripping their quoted flags breaks the requirement that shipped real
  invocation semantics remain denied.
- `sh -c 'rm -rf /'` and `eval 'git reset --hard'` place executable code inside
  single quotes. Removing it erases the only visible destructive invocation.
- Double quotes permit command substitution: `echo "$(rm -rf /tmp/x)"` runs
  the nested command even though its source appears inside a quoted string.
- Here-strings, quoted heredoc delimiters, JSON passed to an interpreter, and
  `--flag=value` have meaning determined by the receiving executable, not by
  their lexical quote form.

This option trades visible false positives for silent false negatives and MUST
NOT be implemented.

### C. Match parsed argv instead of raw text

If a harness supplies an executable plus argv as trusted structured input, the
canonical layer can match executable identity and exact arguments without
searching unrelated data. This is the strongest representation for a direct
exec tool and naturally fixes mention matching in other arguments.

For the current Bash tool, however, no authoritative argv exists before the
shell runs. Producing actual argv requires expansions, environment, filesystem
globbing, functions, aliases, substitutions, and sometimes execution itself.
Running the shell to discover argv would perform the operation before the gate.
A local “argv parser” is therefore only option A under another name.

False-negative and evasion risks:

- Approximated argv disagrees with the real shell for variable and command
  substitution, globbing, aliases, functions, and sourced configuration.
- One argv cannot represent pipelines, `;`, `&&`, subshells, or command
  substitutions; the representation must be an execution graph.
- `eval`, nested shells, `xargs`, `find -exec`, encoded payloads, and
  interpreter calls create later argv that the outer argv does not identify.
- Adapter-specific argv extraction would create different security semantics
  for Claude, Codex, and Grok even though they all submit a Bash string today.

This option SHOULD be used when a future harness provides a genuine direct-exec
operation. It cannot honestly replace shell parsing for the existing Bash tool.

## Recommendation

Adopt option A as a versioned canonical shell-plan contract, not as another
engine prefilter. The adapters should continue only to translate harness wire
formats. The proposed parser is `mvdan.cc/sh/v3/syntax` in Bash mode, pinned to
an exact module version recorded in `ShellPlan.parser_version`. A
harness-neutral canonicalizer should parse the Bash string once and emit an
execution graph containing:

```text
ShellPlan {
  source_digest
  parser_version
  invocations: ShellInvocation[]
  opaque_exec: OpaqueExecution[]
}

ShellInvocation {
  invocation_id, parent_id?
  executable: literal identity
  arguments: shell-word AST[]
  connector: root | pipe | sequence | and | or | substitution | subshell
  cwd_effect: unchanged | literal_cd | unresolved
  source_span
}
```

The plan MUST retain the original command for provenance and preconditions but
MUST NOT use that raw text as invocation identity. Parser version and source
digest prevent adapters and the engine from silently interpreting different
commands.

The shipped TOML rules cannot be safely “compiled” from arbitrary raw regex
into executable and argv predicates. The implementation proposal therefore
needs a versioned rule shape with an exact executable selector and an argument
predicate evaluated only within that invocation. Migration is gated by a
fixture for every shipped deny rule; no rule moves until its real-invocation
equivalence and mention controls pass. Whole-command regex remains available
only for non-Bash tools whose canonical `InputString` is already the identity
being governed, such as a `Read` path.

Wrapper handling must be closed and versioned. Literal bodies for admitted
wrappers such as `sh -c` and `eval` are recursively parsed; dynamic bodies,
unknown wrappers, dynamic command words, and opaque execution handoffs produce
`opaque_exec`, whose eventual policy denial is governed by the mandatory staged
rollout below. `base64 -d | sh` is opaque and is not decoded speculatively. Once
enforcement is gated on, it denies rather than silently opening an evasion that
parsing cannot resolve.

The parser is security attack surface. A parser/real-shell disagreement can
hide a destructive invocation even when policy evaluation is otherwise
correct. Parser upgrades require a new `parser_version`, review, and
differential fixtures against the fleet's supported shell versions. Unsupported
syntax, parse ambiguity, and any known parser/shell disagreement produce a
distinct opaque classification; they MUST NOT become a partial plan that is
treated as ordinary safe work.

## Interaction with existing behavior

- **Bare `git push` on main:** the matcher identifies a literal `git`
  invocation with `push` arguments and then runs the existing branch
  precondition. `GATEKEEPER_INPUT` remains the original command for compatibility,
  while the decision and provenance bind the invocation ID and source span.
- **`cd` prefix:** retain current `ExtractCDPrefix` behavior for the first
  implementation so a leading literal `cd <path> &&` still scopes the
  precondition exactly as today. The shell plan records `cwd_effect`; expanding
  cwd tracking beyond today's leading prefix is a separate reviewed change.
  Dynamic or ambiguous `cd` cannot weaken a denial.
- **Heredocs:** retain current semantics during migration. Data heredoc bodies
  stay outside invocation matching. Bodies supplied to shells/interpreters are
  executable or opaque input, not automatically stripped; literal shell bodies
  may be recursively parsed, while unresolved interpreter behavior is recorded
  and conservatively denied where it can execute commands.
- **Multi-command lines:** each literal command on `;`, `&&`, `||`, and pipeline
  edges is evaluated independently. One denied invocation denies the whole Bash
  tool call; data arguments on one node cannot manufacture an invocation node.
- **Deny wins:** unchanged. An allow on one invocation cannot erase a deny on
  another invocation in the same shell plan.

## Mandatory staged rollout for opaque execution

Opaque classification and opaque denial MUST NOT ship together. The rollout is
an ordered gate:

### Stage 1: shadow classification

The canonicalizer emits `opaque_exec` records, but those records do not change
the existing verdict. Shadow mode records classification metadata and the
exact binary version, source ref, parser version, policy digest, seat ID, and
non-secret source-span digest; it MUST NOT record raw commands, arguments,
credentials, or payload bodies. Shadow mode makes no protection claim.

Shadow measurement is a mandatory precondition of enforcement. It runs for at
least seven consecutive representative fleet-work days, covers at least 90% of
seats active during that window, and observes at least 10,000 Bash tool calls.
Restarting or materially changing the parser, classifier, wrapper registry, or
policy restarts the measurement window against the new exact artifact.

For each opaque class, the report MUST state both event count and rate per Bash
tool call, affected-seat count and rate, and a reviewed classification of the
common cases as legitimate fleet work, suspicious activity, or unresolved:

| reason code | construct measured |
| --- | --- |
| `opaque_dynamic_command_word` | variable, substitution, alias, function, or other non-literal command identity |
| `opaque_unknown_wrapper` | an executable handoff whose argv/body contract is not in the admitted wrapper registry |
| `opaque_dynamic_interpreter_body` | non-literal `eval`, `sh -c`, or equivalent interpreter input |
| `opaque_encoded_handoff` | decoded, generated, piped, or otherwise transformed content handed to an executor |
| `opaque_parser_disagreement` | unsupported syntax, ambiguity, or parser/supported-shell disagreement |

### Stage 2: close common legitimate cases and repeat shadow

If legitimate uses dominate any opaque class, enforcement is blocked. The
admitted-wrapper or canonicalization contract must first expand to cover the
legitimate majority without decoding or executing attacker-controlled content,
then the complete shadow window repeats under the successor versions. A broad
exception such as “allow this seat's opaque commands” is not an admitted
wrapper and cannot satisfy this stage.

### Stage 3: explicit enforcement gate

Opaque denial may be proposed only when a completed shadow report shows all of
the following at one exact artifact generation:

- the remaining legitimate opaque rate is at most 0.1% of Bash calls;
- remaining legitimate opacity affects at most 1% of active seats;
- no known required fleet workflow remains opaque; and
- every unresolved or suspicious class has a reviewed deny reason and an
  independently observed negative control.

Failure of any criterion returns the design to Stage 2; it does not permit a
best-effort launch. Crossing the threshold requires an explicit policy gate and
a separately verified rollback/deactivation path. Shadow success alone never
arms denial.

When enforcement is eventually authorized, the denial message MUST include the
specific reason code above, the unresolvable construct category, and a safe
source location such as invocation ID/source span. A generic “opaque execution”
or “policy denied” message is non-conforming. Messages MUST explain what could
not be resolved without echoing the opaque command or payload. This preserves
actionability without leaking the content being gated.

## Required evidence before implementation can merge

Evidence MUST name the exact source ref and tested binary/build. The deployed
fleet binary is 1.5.1 and is not evidence for a future implementation branch.

1. Enumerate every shipped `decision = "deny"` rule. For every Bash rule, add
   at least one literal real invocation that MUST deny, including quoted forms
   of meaningful flags where the shell accepts them. The non-Bash secret-path
   rule retains its existing direct-tool control. This suite is the
   false-negative gate and MUST be observed failing when a planted invocation
   node or argument predicate is removed.
2. For every blocked Bash pattern, plant non-invocation mentions in a
   single-quoted string, double-quoted string, `echo` argument, JSON payload,
   and `--flag=value`. Each MUST avoid that rule's denial while any independently
   real destructive invocation in the same shell plan still denies.
3. Exercise literal and dynamic command substitutions; literal and dynamic
   `eval`/`sh -c`; variable command and option indirection; `base64 -d | sh`;
   wrappers; pipelines; `;`, `&&`, and `||`; subshells; `xargs`; `find -exec`;
   heredoc data; and executable heredoc bodies. Each case MUST either deny or
   produce a named `opaque_exec` denial. No unsupported case may pass as an
   ordinary no-match.
4. Plant parser/canonicalizer failures and prove the configured fail-closed
   outcome. Because current default `on_error = "abstain"`, this evidence must
   demonstrate an explicit dynamic-execution policy denial, not merely a
   recovered error.
5. Run the same canonical fixtures through every adapter. Their emitted
   `ShellPlan` source digest and invocation graph MUST agree exactly.
6. Plant every opaque reason class and prove shadow mode records without
   enforcing it. Separately plant the enforcement switch and prove each class
   denies with its own reason code. Evidence from either stage MUST name the
   exact binary, source ref, parser version, policy digest, and rollout stage.

## Known residual

Static parsing cannot prove the runtime identity of code hidden behind dynamic
shell state or a general-purpose interpreter. The recommendation contains that
residual first by measuring it and expanding admitted semantics for common
legitimate cases, then—only after the quantitative exit gate—by denying what
remains unresolved rather than pretending to recognize it. Enforcement will
still reject some legitimate dynamic shell programs. That measured,
specifically explained false positive is preferable to an invisible
destructive false negative and must remain visible in reason codes and operator
documentation.
