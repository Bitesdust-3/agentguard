# AgentGuard

AgentGuard is a lightweight AI agent security gateway and automated security evaluation platform for practical AI security and agent security engineering.

> **Project status: Early Development**

## Goal

Build a focused, explainable, and testable security project suitable for public GitHub presentation and security engineering practice. The project prioritizes maintainability and demonstrable security value over feature count.

## Current Status

### Completed

- Public repository foundation and Git initialization.
- Go module initialization.
- Initial open-source documentation and configuration skeleton.
- [v1.0 architecture and core-contract design freeze](docs/architecture-v1.md).

### Implemented infrastructure

- YAML-backed local configuration with safe defaults.
- SQLite connection bootstrap with foreign-key enforcement and versioned schema metadata.
- `GET /health` JSON endpoint.
- OpenAI-style, non-streaming `POST /v1/chat/completions` endpoint.
- Deterministic local Mock Provider for gateway integration; it is not a real LLM.
- Rule-based input Secret detection for a small set of credential-like formats.
- Rule-based input PII detection for email addresses, Chinese mainland mobile numbers, and validated Chinese identity-card numbers.
- Configured input policy enforcement with `PASS`, `REDACT`, and `BLOCK` decisions.
- Privacy-minimized redaction before the provider is called; raw sensitive values are not retained in detection evidence.
- Rule-based, feature-scored direct and basic indirect Prompt Injection detection. It is a deterministic MVP, not a claim of complete protection.
- Input and output safety pipeline: `PASS`, `REDACT`, or `BLOCK` is applied before a provider request and before a provider response reaches the client.
- Output Secret/PII guard with response redaction or safe blocking.
- Configuration-driven Agent Tool Policy decisions using `PASS`, `APPROVAL`, and `BLOCK`.
- Persisted single-step approval workflow and execution-state protection for five controlled Mock/Demo tools.
- Privacy-minimized SQLite security audit trail for Chat requests, detections, policy decisions, Tool Calls, and approvals.
- Stable Chat Request ID and Tool Call ID correlation across persisted audit records.
- Fail-closed audit persistence for critical Chat and pre-execution Tool/Approval paths.
- Local-admin `GET /api/audit/events` API with event, decision, detection, request, tool-call, and limit filters.
- Lightweight local Security Dashboard with overview metrics, security-event filters, request/tool timelines, and Tool/Approval controls.
- Server-rendered Go Templates with HTMX-enhanced event filtering, periodic overview refresh, and existing Approval API actions.
- Deterministic Security Benchmark Runner that reuses production Detector, Policy, and Tool Policy logic.
- Development-scale fixtures plus a 266-case Curated Benchmark v1 covering seven security categories, hard negatives, and boundary cases using fictional data.
- Read-only Benchmark Dashboard view for the latest persisted run, including aggregate and per-category metrics, latency, reproducibility hashes, and privacy-safe failure summaries.

The current Tool Executor is mock-only: it never reads or deletes real files, sends email, queries a database, runs shell commands, or contacts external systems.
- Graceful shutdown for `SIGINT` and `SIGTERM`.

### Planned for v1.0

- One real OpenAI-compatible provider.

## Planned Technology Stack

- Go and the standard library (`net/http`)
- SQLite
- YAML configuration
- Go templates and HTMX
- Go testing tools
- Docker for integration, demo, and release workflows

## Project Structure

```text
.
├── cmd/        # Application entry point
├── configs/    # Safe sample configuration
├── docs/       # Project documentation
├── internal/   # Application, gateway, detection, policy, provider, and storage packages
├── tests/      # Future test assets and integration tests
├── web/        # Future web templates and static assets
├── .env.example
├── .gitignore
├── go.mod
├── LICENSE
└── README.md
```

## Quick Start

From the repository root:

```bash
go run ./cmd/agentguard
```

Then request `http://127.0.0.1:8080/health`.

To exercise the local Mock Provider:

```bash
curl --noproxy '*' -X POST http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"mock-model","messages":[{"role":"user","content":"Hello AgentGuard"}]}'
```

To run the test suite:

```bash
go test ./...
```

Open the local dashboard at `http://127.0.0.1:8080/dashboard`; the persisted Benchmark view is at `/dashboard/benchmark`. The current Audit trail stores privacy-minimized metadata only: it does not retain complete prompts, provider responses, Secrets, PII, or Tool arguments. A real LLM provider is still planned work.

Run the development Benchmark dataset with:

```bash
go run ./cmd/benchmark -dataset tests/benchmark/development.yaml
```

It uses fictional samples only and records privacy-minimized results; the current dataset is for development validation, not final public benchmark claims.

Run the manually reviewed, fictional Curated Benchmark v1 with a fixed seed:

```bash
go run ./cmd/benchmark -dataset tests/benchmark/benchmark-v1.yaml -seed 42
```

The 266 cases are evenly distributed across normal, PII, Secret, direct and indirect Prompt Injection, Tool misuse, and approval-bypass scenarios. They include hard negatives and boundary cases and execute the production Detector, Policy, and Tool Policy implementations. With the default configuration and version `dev`, the current measured detection results are Accuracy `0.911`, Precision `0.950`, Recall `0.854`, FPR `0.040`, and FNR `0.146`; Decision Accuracy is `0.929`. Latency varies by machine and run, so the CLI and Dashboard show the measured average, P50, and P95 rather than a fixed claim.

These results expose real limitations instead of tuning them away: paraphrased direct attacks and email/knowledge-base indirect channels can be missed, some defensive indirect-injection text can be flagged, and current Tool rules do not constrain every target type. AgentGuard does not claim state-of-the-art, comprehensive, enterprise-grade, or 100% safe detection.

## Roadmap

- **Completed:** Repository foundation, health endpoint, OpenAI-style non-streaming gateway, deterministic Mock Provider, and the MVP input Secret/PII detection plus `PASS`/`REDACT`/`BLOCK` policy path.
- **Planned:** One real OpenAI-compatible provider.
- **Future Work:** Consider additional capabilities only after v1.0 is stable and its security value is validated. For future Tools with real external side effects, a final Audit persistence failure after the external action cannot be rolled back by a local SQLite transaction; production designs may consider idempotent external operations, Outbox, or Workflow patterns.

## License

Distributed under the [MIT License](LICENSE).
