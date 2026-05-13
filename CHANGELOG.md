# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-13

First public release. LLM security scanner targeting the OWASP LLM Top 10.

### Added
- Connectors for Anthropic, OpenAI, Ollama, and generic HTTP endpoints via `litellm`
- Behavioral detector with multilingual refusal recognition across 9 languages
- Secret/PII disclosure detector with refusal-phrase false-positive guards
- Scanner modules for LLM01 (prompt injection), LLM02 (data disclosure), LLM06 (excessive agency), LLM07 (system prompt leakage)
- Acrostic-extraction attack scanner
- Guardrail-assessment scanner
- Cost tracker and SQLite-backed scan-history store
- HTML report generator with payload preservation
- Multi-turn conversation scanner for stateful injection chains
- YAML-defined payload and detection rule files
- 240 unit + integration tests across Python 3.10, 3.11, 3.12
- CI: ruff lint, mypy typecheck, pytest, pip-audit
