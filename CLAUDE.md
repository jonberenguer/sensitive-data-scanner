# Project Rules

## Context
Cross-platform sensitive data scanner written in Go. It uses pattern matching (regex) and optional entropy analysis to detect secrets — API keys, tokens, passwords, SSNs, credit card numbers, private keys, and connection strings — in files on a local filesystem. It produces four artifacts per scan: a restricted full report (raw secrets), a redacted text report, a self-contained HTML report, and a structured JSON dataset for security triage.

The pattern library lives in `patterns.json` at the project root and is user-editable without recompilation.

## Tech Stack
- **Language:** Go (stdlib only — no external dependencies)
- **Build:** Docker container (`golang:1.22-alpine`); host does not have Go installed
- **Targets:** Linux amd64, Linux arm64, Windows amd64
- **Source:** `src/` (Go), `node/` (archived Node.js original)
- **Build output:** `build/` (gitignored)

## Conventions
- Stdlib only — justify any external Go dependency before adding it
- Explicit over clever; avoid magic abstractions
- No silent error swallowing — errors surface or are handled explicitly
- Regex patterns live in `patterns.json`, not in source code; use RE2 syntax (no lookaheads/lookbehinds)
- Post-match validators (e.g. `"ssn"`, `"luhn"`) are registered in `scanner.go:validate()` and referenced by name in `patterns.json`
- Full report must be protected: `chmod 600` on Linux/macOS, noted prominently in output

## Build & Run
- All builds go through Docker: `./build.sh` (Linux/macOS) or `.\build.ps1` (Windows)
- Test runs must be done inside Docker containers, not directly on the host
- The binary reads `patterns.json` from the working directory by default; pass `--patterns <path>` to override

## Boundaries
- Do not modify, delete, or quarantine the files being scanned
- Do not transmit findings to any external service or endpoint
- Do not store the full report without explicit user direction — warn about sensitivity at every run
