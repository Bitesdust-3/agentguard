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

No AgentGuard security business capability has been implemented yet.

### Implemented infrastructure

- YAML-backed local configuration with safe defaults.
- SQLite connection bootstrap with foreign-key enforcement and versioned schema metadata.
- `GET /health` JSON endpoint.
- OpenAI-style, non-streaming `POST /v1/chat/completions` endpoint.
- Deterministic local Mock Provider for gateway integration; it is not a real LLM.
- Graceful shutdown for `SIGINT` and `SIGTERM`.

### Planned for v1.0

- OpenAI-compatible API gateway.
- Secret and PII detection.
- Prompt injection detection.
- Input and output security policies.
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
├── cmd/        # Future application entry points
├── configs/    # Future non-sensitive configuration files
├── docs/       # Project documentation
├── internal/   # Future internal packages
├── tests/      # Future test assets and integration tests
├── web/        # Future web templates and static assets
├── .env.example
├── .gitignore
├── go.mod
├── LICENSE
└── README.md
```

The directories above are intentionally empty during this initialization stage. No placeholder files have been added.

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

Security detection, policy decisions, tools, audit features, dashboard, benchmark, and real LLM providers are still planned work.

## Roadmap

- **Completed:** Repository foundation (Phase 0).
- **Planned:** Deliver the approved v1.0 scope incrementally with tests and documentation.
- **Future Work:** Consider additional capabilities only after v1.0 is stable and its security value is validated.

## License

Distributed under the [MIT License](LICENSE).
