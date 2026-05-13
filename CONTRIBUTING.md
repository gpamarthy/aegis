# Contributing

Thanks for considering a contribution.

## Useful contributions

1. **New scanner modules** for OWASP LLM Top 10 categories not yet covered (LLM03 supply chain, LLM05 improper output handling, LLM08 vector store risks, LLM09 misinformation, LLM10 model theft).
2. **New connectors** for LLM APIs beyond Anthropic, OpenAI, Ollama, and generic HTTP.
3. **Refusal phrases** in `aegis/detectors/behavioral.py` for languages not in the current 9-language set.
4. **Test fixtures** with sanitized LLM responses that exercise edge cases.
5. **Payload contributions** under `aegis/payloads/` (YAML files). Include a one-line description of what attack the payload exercises.

## Dev setup

```sh
git clone https://github.com/gpamarthy/aegis
cd aegis
pip install -e .[dev]
make test       # 240/240 pass
make lint       # ruff + mypy
```

## Code style

- Python 3.11+. `ruff check .` and `mypy aegis/` must pass.
- Two-space indent for YAML, four-space for Python.
- No emojis in code or commits. Plain prose in commits, comments, and PR descriptions.
- Conventional commits: `feat(scanners):`, `fix(behavioral):`, `chore:`, `docs:`, `ci:`.

## Adding a scanner

A scanner module lives under `aegis/scanners/llmNN_<category>/` and:

1. Subclasses `ScanBase` from `aegis/scanners/scan_base.py`.
2. Registers itself in `aegis/scanners/registry.py`.
3. Has a test in `tests/` exercising at least one positive and one negative case.
4. Adds an entry to `CHANGELOG.md` under `[Unreleased]`.
