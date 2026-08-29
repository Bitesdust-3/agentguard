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
- Graceful shutdown for `SIGINT` and `SIGTERM`.

### Planned for v1.0

- Prompt injection detection.
- Output detection and output security policy enforcement.
- Agent tool policy engine.
- Audit log and lightweight dashboard.
- Security benchmark.

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
curl --noproxy '*' http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"mock-model","messages":[{"role":"user","content":"Hello AgentGuard"}]}'
```

To run the test suite:

```bash
go test ./...
```

Prompt injection, output-side protections, tools, audit features, dashboard, benchmark, and real LLM providers are still planned work.

## Roadmap

- **Completed:** Repository foundation, health endpoint, OpenAI-style non-streaming gateway, deterministic Mock Provider, and the MVP input Secret/PII detection plus `PASS`/`REDACT`/`BLOCK` policy path.
- **Planned:** Prompt injection detection, output detection/policy, tool policy, audit, dashboard, benchmark, and one real OpenAI-compatible provider.
- **Future Work:** Consider additional capabilities only after v1.0 is stable and its security value is validated.

## License

Distributed under the [MIT License](LICENSE).
