# Bounded Second-Opinion Review

Status: experimental implementation for [RFC #3174](https://github.com/affaan-m/ECC/issues/3174).

## Purpose

ECC already has first-party review workflows and a provider-neutral Python LLM
abstraction. This feature adds a different primitive: an explicit boundary for
asking an independent reviewer to inspect a bounded evidence packet and return
structured advisory findings.

It replaces the manual workflow of copying a plan, diff, failure, or
verification result into another model and copying its findings back into the
primary Claude Code session. It is not a general model-to-model conversation
bus.

## Trust Model

There are three distinct trust domains:

~~~text
Claude Code / ECC
      |
      | constructs and scans bounded evidence
      v
configured reviewer executable
      |
      | invokes an external/local model as configured by the user
      v
untrusted ReviewResult
      |
      | local verification
      v
Claude Code / executable evidence
~~~

The configured reviewer executable is **user-trusted transport**. ECC launches
it without a shell, from a temporary-directory working directory, and with a
minimized environment plus only explicitly allowed environment-variable names.
ECC does not grant repository-write or shell authority through the review
protocol.

An arbitrary executable intentionally configured by the user is still a local
process and is not an operating-system sandbox. Users must only configure
reviewer executables they trust.

The reviewer model and its output are **untrusted peer-review input**. A finding
does not become actionable merely because the reviewer marks it high or
critical. Claude must verify material findings against the current repository
and, where practical, executable evidence.

## Protocol

The request schema is schemas/cross-review-request.schema.json with identifier:

~~~text
ecc.review.request.v1
~~~

A request contains a review mode (plan, diff, failure, or final), an objective,
one to eight bounded evidence items, a maximum-finding constraint, and an
immutable advisory trust declaration.

Each evidence item has a stable ID, kind, source label, and text content. The
runtime caps individual evidence size, total evidence characters, and the final
UTF-8 request payload at 256 KiB. String bounds are enforced consistently across
the JSON schemas, Node runtime, and Python reference adapter.

The result schema is schemas/cross-review-result.schema.json with identifier:

~~~text
ecc.review.result.v1
~~~

A finding contains a stable ID, severity, category, falsifiable claim,
references to evidence IDs that were actually sent, and a deterministic
verification suggestion. The runtime rejects findings that cite an evidence ID
outside the request.

## Explicit Invocation

External review is never triggered by file edits, tool failures, Stop hooks, or
background automation in this version.

~~~bash
ecc cross-review diff --dry-run --json
ecc cross-review diff --json

ecc cross-review plan \
  --evidence plan:plan=.claude/plans/feature.md \
  --json

ecc cross-review failure \
  --evidence failure:test-output=/tmp/test-failure.txt \
  --json

ecc cross-review final \
  --diff \
  --evidence test:verification=/tmp/verification.txt \
  --json
~~~

The slash-command compatibility surface is /cross-review. Its Node CLI and
protocol runtime are owned by commands-core so minimal/selective command
installs do not depend on hooks-runtime.

## Configuration

Reviewer configuration is user-scoped by default rather than repository-scoped.
This is deliberate: automatically executing a command selected by repository
content would turn a cloned repository into a command-execution authority.

~~~bash
ecc cross-review status --json
~~~

Configure the reference ECC LLM adapter after installing the Python package:

~~~bash
ecc cross-review configure \
  --command llm-review-adapter \
  --pass-env LLM_PROVIDER \
  --pass-env LLM_MODEL \
  --pass-env OPENAI_API_KEY
~~~

The configuration stores environment-variable **names**, not their values.
High-confidence secret-like values in reviewer arguments are rejected and must
be supplied through an explicitly allowlisted environment variable instead.

A different executable can implement the same stdin/stdout protocol, including
an Amazon Bedrock adapter, a local-model adapter, or an internal enterprise
review service. ECC core does not need a provider SDK for each one.

## Existing LLMProvider Integration

src/llm/review/adapter.py is a reference adapter over ECC's existing Python
provider layer:

~~~text
ReviewRequest
    |
    v
get_provider() -> LLMProvider
    |
    v
LLMOutput
    |
    v
strict ReviewResult validation
~~~

Provider selection continues to use the existing LLM_PROVIDER and LLM_MODEL
configuration. Provider credentials remain environment variables; they are not
copied into request evidence.

The Node ecc cross-review runtime intentionally does not import provider SDKs.
This keeps the npm runtime provider-neutral and permits local or
organization-specific reviewers behind the same protocol.

## Data Boundary and Secret Handling

Before external invocation, ECC performs deterministic checks for dotenv files,
credential/secret file names, private-key files, SSH private-key names, AWS
credential files, npm credential files, private-key blocks, AWS secret access
keys, bearer authorization headers, common OpenAI/GitHub/Slack token formats,
and sensitive paths embedded in unified-diff headers.

High-confidence matches fail closed across the outbound objective, evidence
IDs, source labels, diff headers, and evidence content. This version does not
ask an LLM to decide whether a value is secret.

The --dry-run option builds and validates the real packet, performs the same
secret scan, and reports only metadata such as evidence IDs, source labels, and
character counts. It always reports:

~~~text
No data transmitted.
~~~

For diff mode, ECC uses:

~~~bash
git diff --no-ext-diff --no-textconv --no-color HEAD --
~~~

This includes tracked staged and unstaged changes. Untracked files are excluded
unless the user explicitly supplies one with --evidence.

## Reviewer Process Boundary

The reviewer command is launched with shell disabled, an argument array rather
than shell interpolation, a temporary-directory working directory rather than
the project root, a bounded timeout, a bounded output buffer, and a minimal
environment plus the configured passEnv allowlist. Home-profile variables such
as HOME, USERPROFILE, and APPDATA are not inherited by default; a user must
explicitly allow them when a trusted reviewer genuinely requires them.

Reviewer failure, timeout, non-zero exit, malformed JSON, schema mismatch, or
invalid evidence provenance fails the external review without weakening normal
ECC behavior. No credential value is printed by status or written by configure.

## Verification Lifecycle

A reviewer finding can move through these local reconciliation states:

~~~text
OPEN -> VERIFIED -> FIXED -> REGRESSION_TESTED
   \-> REJECTED
~~~

The truth hierarchy remains:

~~~text
requirements and explicit contracts
        |
repository state and invariants
        |
tests / executable evidence
        |
model interpretations
~~~

## Non-Goals

This version does not provide autonomous Claude-to-model conversation loops,
automatic Stop/PostToolUse review hooks, reviewer repository-write access,
reviewer shell/tool execution through the protocol, whole-session transcript
export, automatic provider installation or credential discovery, a native
Bedrock SDK dependency, automatic acceptance of reviewer findings, or
multi-reviewer consensus/judging.

Those can be evaluated separately only if the explicit bounded primitive proves
useful and the trust boundary remains clear.

## Future Evaluation

Useful measurements before adding automation include manual context transfers
avoided, review latency, confirmed findings unique to the second reviewer,
rejected/false-positive findings, repeated failures resolved, wall-clock impact,
and provider cost.

Repeated-failure or milestone-triggered review should remain a follow-up design,
not an implicit behavior of this initial boundary.
