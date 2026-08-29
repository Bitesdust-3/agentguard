# AgentGuard v1.0 Architecture and Core Contracts

**Status:** Frozen design for Phase 1 — implementation has not started.

This document freezes the minimum contracts that implementation must follow. Changes to the pipeline, the four decision actions, the entities below, the tool-call state machine, or the public API require an impact review before coding.

## 1. v1.0 Boundary

### Included

1. A non-streaming, OpenAI-compatible `POST /v1/chat/completions` gateway.
2. Secret and PII detection on input and output.
3. Direct and indirect prompt-injection detection.
4. Input and output policy decisions using `PASS`, `REDACT`, `BLOCK`, and `APPROVAL`.
5. An allow-listed agent tool policy engine and approval flow.
6. Append-only audit records and a lightweight local dashboard.
7. A deterministic security benchmark with stored results.

### Explicitly excluded

RAG security, MCP, provider marketplaces, multi-tenancy, IAM/RBAC, local model hosting or training, microservices, queues, clusters, billing, and a large SPA frontend are Future Work. v1.0 supports exactly two provider implementations: one Mock Provider and one OpenAI-compatible Provider.

## 2. Architecture and Responsibilities

AgentGuard is a modular monolith: one Go process, `net/http`, one SQLite database, file-based YAML configuration, Go templates, and HTMX. Modules call interfaces in-process; no internal HTTP services or message broker are introduced.

```text
Client
  -> Gateway
  -> Input Detection
  -> Input Policy Decision
  -> LLM Provider
  -> Output Detection
  -> Output Policy Decision
  -> Response
  -> Audit
```

The tool path is separate from the text path:

```text
Agent / LLM -> Tool Call Request -> Tool Policy Evaluation
  -> PASS -> controlled Tool Executor -> Audit
  -> APPROVAL -> Pending Approval -> Approved -> controlled Tool Executor -> Audit
  -> BLOCK -> Audit
```

| Module | Sole responsibility | Must not do |
| --- | --- | --- |
| Gateway | Validate the supported API shape, assign request IDs, orchestrate the fixed pipeline, return protocol responses. | Contain detection rules or tool permissions. |
| Detector | Report structured risk facts from content. | Decide `PASS`, `REDACT`, `BLOCK`, or `APPROVAL`. |
| Policy Engine | Map risk facts and configuration to a `PolicyDecision`. | Scan raw content or call a provider. |
| Provider | Convert a sanitized chat request to a model response. | Persist audit data or make security decisions. |
| Tool Policy | Evaluate normalized tool metadata and arguments against YAML policy. | Execute a tool. |
| Tool Executor | Invoke only a registered, allow-listed demo tool after state authorization. | Re-evaluate or override a policy/approval decision. |
| Audit | Append privacy-minimized, ordered event facts for each stage. | Become a source of truth for mutable workflow state. |
| Dashboard | Read stored data and render it. | Drive database schema or make policy decisions. |
| Benchmark | Run immutable fixture cases through the same pipeline and compute metrics. | Use hand-entered results. |

## 3. Security Pipeline Contract

1. The gateway normalizes a request and creates `RequestID`.
2. Input detectors return zero or more `DetectionResult` values; no detector mutates the request.
3. Input policy returns one `PolicyDecision`. `BLOCK` stops the provider call. `REDACT` produces a redacted provider payload. `PASS` continues. `APPROVAL` is not a valid text-gateway outcome in v1.0 and is treated as a configuration error; it is reserved for tools.
4. The provider is called only after a non-blocking input decision.
5. Output detectors and output policy repeat the same process. `BLOCK` returns a safe gateway error; `REDACT` returns the redacted response.
6. Audit events are appended for every terminal path, including provider failures. Audit writes must not change a security decision; failure to audit makes the request fail closed with a server error.

Each detector invocation and policy evaluation receives the immutable subject ID and stage (`INPUT`, `OUTPUT`, or `TOOL`). No caller may skip a stage.

## 4. Frozen Vocabulary and Wire Conventions

| Concept | Frozen name / values |
| --- | --- |
| Decision action | `PASS`, `REDACT`, `BLOCK`, `APPROVAL` |
| Detection type | `PII`, `SECRET`, `PROMPT_INJECTION` |
| Detection source | `INPUT`, `OUTPUT`, `TOOL_ARGUMENT` |
| Policy stage | `INPUT`, `OUTPUT`, `TOOL` |
| Tool states | `RECEIVED`, `EVALUATED`, `PASS`, `BLOCK`, `PENDING_APPROVAL`, `APPROVED`, `REJECTED`, `EXECUTED`, `FAILED` |
| Approval status | `PENDING`, `APPROVED`, `REJECTED` |
| Benchmark run status | `RUNNING`, `COMPLETED`, `FAILED` |
| Core entity names | `Request`, `DetectionResult`, `PolicyDecision`, `ToolCall`, `Approval`, `AuditEvent`, `BenchmarkRun`, `BenchmarkResult` |

IDs are opaque text IDs. API timestamps use UTC RFC 3339 with nanoseconds; SQLite stores the same UTC timestamp as `TEXT`. Scores and confidence are decimal values in the closed interval `[0,1]`. JSON field names are lower snake case.

## 5. Core Data Models

### 5.1 `DetectionResult`

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Opaque result ID. |
| `subject_type` | yes | `REQUEST` or `TOOL_CALL`. |
| `subject_id` | yes | Request or tool-call ID that was inspected. |
| `detection_type` | yes | `PII`, `SECRET`, or `PROMPT_INJECTION`. |
| `rule_id` | yes | Stable detector rule identifier, for example `pii.email.v1`. |
| `score` | yes | Detector risk score in `[0,1]`. |
| `confidence` | yes | Detector confidence in `[0,1]`; distinct from risk severity. |
| `evidence` | yes | Short masked excerpt or safe explanation; never full sensitive source text. |
| `source` | yes | `INPUT`, `OUTPUT`, or `TOOL_ARGUMENT`. |
| `metadata` | no | Small JSON object containing safe details such as match count or character offsets. |
| `created_at` | yes | UTC creation timestamp. |

Evidence is minimized: secrets show a type and last four characters at most; PII shows a masked value; injection evidence stores the matched rule phrase or location, not an entire user prompt. Raw request/response bodies are not stored by default.

### 5.2 `PolicyDecision`

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Opaque decision ID. |
| `subject_type` / `subject_id` | yes | Subject governed by this decision. |
| `stage` | yes | `INPUT`, `OUTPUT`, or `TOOL`. |
| `decision` | yes | One of the four frozen actions. |
| `policy_id` | yes | Stable policy rule or default, for example `input.default.v1`. |
| `reason` | yes | Human-readable, privacy-minimized rationale. |
| `risk_score` | yes | Aggregated policy risk in `[0,1]`. |
| `matched_rules` | yes | Ordered array of rule IDs used by the decision. |
| `redactions` | no | Ordered safe replacement operations; present only for `REDACT`. |
| `approval_required` | yes | `true` only for tool `APPROVAL`. |
| `created_at` | yes | UTC creation timestamp. |

`matched_rules` and `redactions` are kept as JSON in SQLite but exposed as arrays in APIs. A redaction stores a replacement label and safe location metadata, never the original secret.

### 5.3 Other entities

- **Request:** one gateway attempt; stores a model label, request fingerprint, lifecycle timestamps, final action, and only privacy-minimized payload summaries.
- **ToolCall:** one normalized request to a registered tool; stores declared risk attributes, masked arguments, policy decision reference, lifecycle state, and an execution idempotency key.
- **Approval:** one approval record per approval-required tool call; stores status, reviewer label, reason, and decision time.
- **AuditEvent:** immutable event with a subject reference, event type, safe summary, actor label, and timestamp.
- **BenchmarkRun:** one reproducible execution over a named dataset version, configuration hash, provider mode, seed, and timing window.
- **BenchmarkResult:** one case result linked to a run, with expected/observed outcomes, pass flags, and per-case timing.

## 6. Tool Call and Approval State Machines

Decision, approval, and execution are separate concerns. `PolicyDecision.decision` answers *what policy chose*; `Approval.status` answers *whether a required human decision happened*; `ToolCall.state` is the authoritative lifecycle and execution gate.

### 6.1 Legal transitions

```text
RECEIVED -> EVALUATED
EVALUATED -> PASS | BLOCK | PENDING_APPROVAL
PENDING_APPROVAL -> APPROVED | REJECTED
PASS -> EXECUTED | FAILED
APPROVED -> EXECUTED | FAILED
```

`BLOCK`, `REJECTED`, `EXECUTED`, and `FAILED` are terminal. `PASS` and `APPROVED` are executable authorization states, not terminal states.

### 6.2 Enforcement rules

- Only evaluation can transition `RECEIVED -> EVALUATED` and choose the next state.
- An executor may run only a call currently in `PASS` or `APPROVED`, and atomically claims the execution idempotency key before invocation.
- An approval endpoint may transition only `PENDING_APPROVAL -> APPROVED|REJECTED`; it cannot invoke an executor or alter a policy decision.
- A blocked or rejected call has no legal path to an executable state. A retry is a new `ToolCall` with a new ID.
- Every transition appends one `AuditEvent` in the same database transaction as the state update.
- v1.0 tools are fixed demo tools: `weather.read`, `file.read`, `email.send`, `database.query`, and `file.delete`. They are registered explicitly; no arbitrary command, URL, or function execution exists.

## 7. Provider Contract and Mock Mode

The provider boundary has only one operation conceptually: receive a normalized, already-approved chat request and return a normalized chat completion or a typed provider error. Its minimum request fields are `request_id`, `model`, `messages`, and supported generation options (`temperature`, `max_tokens`); its response contains `id`, `model`, one assistant message, `finish_reason`, and optional normalized tool-call proposals.

The gateway owns OpenAI protocol translation. Provider implementations do not see raw HTTP requests and cannot choose security actions.

### Mock Provider

- Selected by `provider.mode: mock`; it needs no API key or network.
- Returns deterministic responses selected by safe fixture scenario IDs or stable input fixtures, not random text.
- Can propose registered demo tool calls only. Its mock executor never sends email, deletes files, queries a real database, or reads arbitrary paths.
- Runs the normal detection, policy, approval, audit, dashboard, and benchmark paths; only upstream inference is replaced.
- Enables five demos: normal request (`PASS`), fictional secret/PII (`REDACT`), injection (`BLOCK`), controlled tool approval/block, and a real locally executed benchmark.

The only real provider in v1.0 is `openai_compatible`, configured with a base URL, model, timeout, and an environment-variable reference for a key. No provider plugin registry is designed.

## 8. API Contract

All management endpoints are internal local-admin APIs under `/api`. In v1.0 the admin listener defaults to loopback; exposing it beyond loopback is not a supported deployment mode until authentication is designed. Responses include `X-AgentGuard-Request-ID` when a request ID exists.

| Method / path | Audience | Purpose | Main request / response fields |
| --- | --- | --- | --- |
| `GET /health` | public | Liveness check. | Response: `status`, `version`, `provider_mode`. |
| `POST /v1/chat/completions` | OpenAI-compatible | Run the fixed text security pipeline. | Request subset: `model`, `messages`, optional `temperature`, `max_tokens`, `stream:false`. Response: standard `chat.completion` shape; security details remain in audit, not compatibility payloads. |
| `GET /api/dashboard/summary` | local admin | Read aggregate counts and recent safety decisions. | Response: time window, action counts, recent event summaries. |
| `GET /api/audit/events` | local admin | List audit events. | Query: `request_id`, `tool_call_id`, `limit`, `cursor`; response: `items`, `next_cursor`. |
| `GET /api/audit/events/{id}` | local admin | Read one privacy-minimized event. | Response: one `AuditEvent`. |
| `POST /api/tool-calls` | local admin / demo agent | Submit a normalized registered tool request for evaluation. | Request: `request_id`, `tool_name`, `arguments`, `target_type`, `is_external`, `is_destructive`, `is_sensitive`; response: `tool_call_id`, `state`, `decision`, `approval_id` when relevant. |
| `GET /api/tool-calls/{id}` | local admin | Read tool lifecycle and policy result. | Response: `ToolCall`, associated decision, safe arguments, approval summary. |
| `GET /api/approvals` | local admin | List pending/recent approvals. | Query: `status`, `limit`, `cursor`; response: `items`, `next_cursor`. |
| `POST /api/approvals/{id}/approve` | local admin | Approve exactly one pending request. | Request: optional safe `reason`; response: updated `Approval` and `ToolCall` state `APPROVED`. |
| `POST /api/approvals/{id}/reject` | local admin | Reject exactly one pending request. | Request: optional safe `reason`; response: updated `Approval` and `ToolCall` state `REJECTED`. |
| `POST /api/benchmark-runs` | local admin | Start a named fixed dataset run. | Request: `dataset_version`, optional `seed`; response: `benchmark_run_id`, `status`. |
| `GET /api/benchmark-runs/{id}` | local admin | Read run metadata and aggregate metrics. | Response: `BenchmarkRun`, metrics, category summary. |
| `GET /api/benchmark-runs/{id}/results` | local admin | Page through case results. | Query: `category`, `limit`, `cursor`; response: `items`, `next_cursor`. |

Unsupported Chat Completions features, including streaming, are rejected explicitly rather than silently ignored. Compatible errors use an `error` object with `message`, `type`, and stable `code`; a blocked request uses `code: security_blocked` without returning sensitive evidence.

## 9. SQLite Logical Schema

This is a table design, not a migration. Foreign keys are enabled on every SQLite connection; SQLite requires explicit per-connection enforcement.

| Table | Why it is independent | Key fields and relations | Necessary indexes |
| --- | --- | --- | --- |
| `requests` | Gateway lifecycle is the parent trace. | `id` PK, `model`, `request_fingerprint`, `input_summary`, `output_summary`, `final_decision`, `created_at`, `completed_at`. | `created_at`; `final_decision, created_at`. |
| `detections` | One request can have many detector facts across stages. | `id` PK, `request_id` FK nullable for tool subject, `tool_call_id` FK nullable, fields from `DetectionResult`. Exactly one subject ID is populated. | `request_id, created_at`; `tool_call_id, created_at`; `detection_type, rule_id`. |
| `policy_decisions` | Decisions need independent explanations and can govern requests or tools. | `id` PK, `request_id` or `tool_call_id`, `stage`, `decision`, `policy_id`, `risk_score`, JSON fields, `created_at`. | `request_id, stage, created_at`; `tool_call_id, created_at`; `decision, created_at`. |
| `tool_calls` | Tool lifecycle is mutable and must be execution-gated. | `id` PK, `request_id` FK nullable, normalized tool fields, masked arguments, `state`, `policy_decision_id` FK, `execution_key` unique, timestamps. | `state, updated_at`; `request_id, created_at`; unique `execution_key`. |
| `approvals` | One-to-one human decision with distinct lifecycle. | `id` PK, `tool_call_id` FK unique, `status`, `reviewer`, `reason`, `created_at`, `decided_at`. | unique `tool_call_id`; `status, created_at`. |
| `audit_events` | Append-only history is queried independently from mutable state. | `id` PK, `request_id`/`tool_call_id` nullable, `event_type`, `actor`, `summary`, `created_at`. | `request_id, created_at`; `tool_call_id, created_at`; `created_at`. |
| `benchmark_runs` | Reproducibility metadata belongs to a run, not a request. | `id` PK, `dataset_version`, `config_hash`, `provider_mode`, `seed`, `status`, timestamps. | `created_at`; `dataset_version, config_hash`. |
| `benchmark_results` | Each case must remain traceable and queryable. | `id` PK, `benchmark_run_id` FK, `case_id`, `category`, expected/observed JSON, pass flags, latency fields. | `benchmark_run_id, category`; unique `benchmark_run_id, case_id`. |

`requests`, `detections`, `policy_decisions`, `tool_calls`, `approvals`, `audit_events`, `benchmark_runs`, and `benchmark_results` are all required logical tables. No separate users, roles, providers, tools catalog, redaction, dashboard, or metrics tables are created in v1.0. Tool policy lives in YAML; dashboard aggregates existing records; redactions remain part of `policy_decisions`.

## 10. YAML Configuration Contract

One human-readable YAML file is sufficient. Secrets are not YAML values: the real-provider key is read from the named environment variable.

```yaml
server:
  listen_addr: "127.0.0.1:8080"
  admin_listen_addr: "127.0.0.1:8080"

provider:
  mode: mock # mock | openai_compatible
  model: agentguard-mock
  timeout_ms: 15000
  openai_compatible:
    base_url: "https://example.invalid/v1"
    api_key_env: AGENTGUARD_OPENAI_API_KEY

detection:
  pii:
    enabled: true
    threshold: 0.80
  secret:
    enabled: true
    threshold: 0.80
  prompt_injection:
    enabled: true
    threshold: 0.75

policy:
  input:
    default_action: PASS
    rules:
      - id: input.secret.v1
        when: {detection_type: SECRET, min_score: 0.80}
        action: REDACT
      - id: input.injection.v1
        when: {detection_type: PROMPT_INJECTION, min_score: 0.75}
        action: BLOCK
  output:
    default_action: PASS
    rules:
      - id: output.sensitive.v1
        when: {detection_type: PII, min_score: 0.80}
        action: REDACT

tools:
  default_action: BLOCK
  rules:
    - id: tool.weather.read.v1
      match: {name: weather.read}
      action: PASS
    - id: tool.email.send.v1
      match: {name: email.send, external: true}
      action: APPROVAL
    - id: tool.file.delete.v1
      match: {name: file.delete, destructive: true}
      action: BLOCK

audit:
  retention_days: 30
  store_raw_content: false

benchmark:
  dataset_version: v1
  seed: 42
```

Tool `match` supports only `name`, `target_type`, `external`, `destructive`, and `sensitive`. Rules are first-match wins; a `default_action` is mandatory. No expression language, wildcard DSL, or code execution is permitted.

## 11. Benchmark Contract

### 11.1 Dataset case format

The future fixture format is YAML or JSON and contains only fictional, hand-reviewed values:

```yaml
id: pii-email-001
category: pii
input: "Please summarize contact: demo.user@example.test"
expected_detection: true
expected_decision: REDACT
expected_rule: pii.email.v1
notes: "Fictional reserved-domain address."
```

Required fields are `id`, `category`, `input`, `expected_detection`, `expected_decision`, `expected_rule`, and `notes`. Categories are `normal`, `pii`, `secret`, `direct_prompt_injection`, `indirect_prompt_injection`, `tool_misuse`, and `approval_bypass`. For tool categories, `expected_detection` may be `null`; correctness is evaluated through expected policy decision and state outcome. Indirect-injection cases include a fictional untrusted-context field in addition to `input` when fixtures are created.

### 11.2 Metrics

- **Detection accuracy:** `(TP + TN) / (TP + TN + FP + FN)` for each detector category with a binary expected-risk label.
- **Precision:** `TP / (TP + FP)`; report `N/A` when no positive predictions exist.
- **Recall:** `TP / (TP + FN)`; report `N/A` when a category has no expected positives.
- **False Positive Rate:** `FP / (FP + TN)`, calculated on the `normal` and relevant negative cases.
- **False Negative Rate:** `FN / (FN + TP)`, calculated per applicable risk category.
- **Decision accuracy:** exact match of observed versus expected `PASS`, `REDACT`, `BLOCK`, or `APPROVAL` divided by all cases with an expected decision.
- **Tool-state accuracy:** exact expected terminal/non-terminal state match for tool and approval-bypass fixtures.
- **Added latency:** protected pipeline elapsed time minus an otherwise identical baseline provider call. Report median and p95 in milliseconds; never combine Mock and real-provider latency in one aggregate.

For multi-category reporting, calculate each detector category one-vs-rest, publish the per-category confusion counts, macro-average valid category metrics, and the micro aggregate across all applicable cases. Decision accuracy remains a separate four-class metric, so a correct risk detection but wrong action is visible.

Every run stores dataset version, fixture content hash, YAML configuration hash, provider mode/model, seed, software version, start/end timestamps, and raw counts. Results are computed from stored case outcomes only; no manual editing or invented metric is permitted.

## 12. Demo Data Plan

The future seed set is generated from versioned fictional fixtures and contains no real emails, keys, IPs, customers, or files.

| Demo | Fictional input / action | Expected outcome |
| --- | --- | --- |
| Normal request | A generic travel question. | `PASS`. |
| Sensitive input | Reserved-domain email and clearly synthetic token pattern. | `REDACT`. |
| Direct injection | A fictional instruction attempting to override system rules. | `BLOCK`. |
| Tool action | `email.send` requires approval; `file.delete` is blocked. | `APPROVAL` or `BLOCK`. |
| Benchmark | Fixed fixtures covering all seven categories. | Stored, computed metrics. |

## 13. Recommended Final Directory Structure

This is the target structure for later approved implementation; this phase does not create the listed implementation files.

```text
.
├── cmd/
│   └── agentguard/             # process entry point
├── configs/                    # safe sample YAML only
├── docs/
│   └── architecture-v1.md
├── internal/
│   ├── app/                    # composition and lifecycle
│   ├── gateway/                # HTTP compatibility boundary
│   ├── detection/              # detectors and shared result types
│   ├── policy/                 # text and tool policy evaluation
│   ├── provider/               # mock and OpenAI-compatible implementations
│   ├── tools/                  # registry, approval gate, controlled executors
│   ├── audit/                  # audit service and query model
│   ├── benchmark/              # fixture runner and metric calculation
│   ├── storage/                # SQLite repositories and migrations later
│   └── web/                    # dashboard handlers and view models
├── tests/                      # integration fixtures and end-to-end tests
├── web/
│   ├── static/
│   └── templates/
├── .env.example
├── go.mod
└── README.md
```

Shared domain types initially live in the smallest owning package: detection owns `DetectionResult`, policy owns `PolicyDecision`, tools owns `ToolCall` and `Approval`, audit owns `AuditEvent`, and benchmark owns its run/result types. A generic `models` package is intentionally avoided until actual import pressure proves it necessary.

## 14. Future Work Boundary

Future Work may consider streaming compatibility, more providers, richer authentication, RAG/MCP protections, external tool integrations, distributed execution, broader benchmark corpora, and UI expansion. None may change v1.0 contracts implicitly; each requires a reviewed proposal, especially if it introduces new decisions, entities, tables, or state transitions.

## 15. Rework-Risk Review and Guardrails

1. **Raw-content retention:** raw prompts, outputs, arguments, and evidence are the largest privacy risk. Default to masked summaries and explicit `store_raw_content: false`; never make dashboard convenience a reason to store raw content.
2. **Tool state ambiguity:** keeping decision, approval, and execution in one field would enable bypasses. Preserve the separate `PolicyDecision`, `Approval`, and `ToolCall.state` contracts and enforce legal transitions transactionally.
3. **Overbuilt APIs:** do not add CRUD endpoints for every table. The listed read/query endpoints and three workflow commands are sufficient; dashboard uses them rather than inventing a backend-specific contract.
4. **Schema fragmentation:** do not create separate dashboard, rule-match, redaction, provider, or user tables in v1.0. JSON metadata is acceptable for small explainability fields; relations above remain explicit where lifecycle or queryability requires them.
5. **Benchmark drift:** a benchmark must execute the production pipeline, pin fixture/config hashes and provider mode, and report confusion counts. Do not create a separate detector-only benchmark that cannot validate decisions or tool approval paths.
6. **Provider coupling:** normalize only the minimal Chat Completions subset at the gateway/provider boundary. Avoid leaking provider-specific request types into detection, policy, storage, or audit.
7. **Dashboard-driven schema changes:** dashboard is a read model over audit and core tables. New visualizations first use existing fields; a new core column needs an impact review across API, audit, benchmark, and fixtures.
8. **Configuration complexity:** fixed YAML fields and first-match tool rules prevent a future DSL from becoming a hidden policy runtime. New matching dimensions require an explicit threat-model and contract change.

## 16. Design Inputs

The compatible gateway retains the documented Chat Completions request/response and tool-call concepts while intentionally supporting only a small non-streaming subset. The benchmark contract borrows the useful separation of targets, categories, expected outcomes, and repeatable configuration from public LLM red-team/evaluation practice, without importing their broad provider/plugin scope.

- [OpenAI Chat Completions API reference](https://developers.openai.com/api/reference/resources/chat)
- [SQLite foreign-key documentation](https://www.sqlite.org/foreignkeys.html)
- [Promptfoo red-team configuration](https://github.com/promptfoo/promptfoo/blob/main/site/docs/red-team/configuration.md)
