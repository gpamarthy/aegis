# Aegis

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

**AI Exploitation & Guardrail Inspection Suite**

Aegis is a comprehensive security scanner for Large Language Model (LLM) applications. It surfaces vulnerabilities such as prompt injection, sensitive information disclosure, and improper output handling by probing endpoints with specialized payloads and monitoring responses against a robust suite of detectors.

## ⚠️ Disclaimer

This tool is for legal, authorized security testing only. The authors are not responsible for misuse or damage caused by this tool. All testing should be performed in accordance with local laws and organizational policies.

## Features

- **Multi-Model Support**: Powered by `litellm`, Aegis scans OpenAI, Anthropic, Ollama, and generic HTTP endpoints.
- **YAML-Based Detection**: Patterns and indicators are managed in declarative YAML files for easy tuning.
- **Stateful Analysis**: Scan findings and telemetry are persisted in a local SQLite database for historical tracking.
- **SIEM-Ready Logging**: Structured JSON logging via `structlog` for integration with modern security operations.
- **OWASP Top 10 for LLM**: Scanners mapped to OWASP LLM vulnerabilities (Prompt Injection, Sensitive Data Leakage, etc.).
- **Interactive Reports**: Generates professional HTML and JSON reports.

## Installation

```bash
# Clone the repository
git clone https://github.com/gpamarthy/aegis.git
cd aegis

# Install in editable mode with dev dependencies
pip install -e .[dev]
```

## Quick Start

```bash
# List available scanners
aegis list-scanners

# Run a quick scan against an OpenAI model
aegis scan -t https://api.openai.com/v1/chat/completions -p openai -m gpt-4o-mini -k YOUR_API_KEY --profile quick
```

## Usage

```bash
aegis scan [OPTIONS]

Options:
  -t, --target TEXT       Target LLM endpoint URL [required]
  -p, --provider [openai|anthropic|ollama|http]
                          LLM provider  [default: openai]
  -m, --model TEXT        Model name  [default: gpt-4o-mini]
  -k, --api-key TEXT      API key (or set AEGIS_API_KEY)
  --profile [quick|standard|full|stealth]
                          Scan profile  [default: quick]
  --budget FLOAT          Maximum spend in USD  [default: 5.0]
  -o, --output TEXT       Output file path  [default: aegis_report.html]
  --format [html|json]    Report format  [default: html]
  --scanners TEXT         Comma-separated scanner names (overrides profile)
  --concurrency INTEGER   Max concurrent scanner tasks  [default: 5]
  --timeout FLOAT         Per-request timeout in seconds  [default: 30.0]
  -v, --verbose           Enable debug logging
  --help                  Show this message and exit.
```

## Architecture

Aegis follows a modular pipeline:
1. **Connectors**: Handle communication with various LLM providers.
2. **Payloads**: Specialized strings designed to bypass guardrails or trigger vulnerabilities.
3. **Scanners**: Orchestrate the injection of payloads and collection of responses.
4. **Detectors**: Analyze responses for indicators of compromise or leakage.
5. **Reporters**: Consolidate findings into actionable summaries.

## Data Persistence

Aegis stores all scan metadata, telemetry, and findings in `~/.aegis/aegis.db` by default.

## License

Distributed under the MIT License. See `LICENSE` for more information.
