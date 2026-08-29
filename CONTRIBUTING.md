# Contributing

Thank you for helping improve AgentGuard. Keep changes small, explainable, and within the documented architecture.

## Development environment

- Go 1.27
- A C compiler for `go-sqlite3`
- Docker with Compose v2 for container checks

Run the local service in key-free Mock mode:

```bash
go run ./cmd/agentguard -config configs/config.example.yaml
```

Before proposing a change, run:

```bash
go test -count=1 ./...
go vet ./...
git diff --check
```

Commits should have one clear purpose and avoid unrelated rewrites. Add regression tests for security-sensitive bug fixes.

Never commit API keys, tokens, passwords, cookies, `.env` files, runtime SQLite databases, complete prompts or Provider responses, real PII, or real organizational data. Fixtures and demos must be fictional and clearly identifiable as test data.
