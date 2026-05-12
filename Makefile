.PHONY: install lint test clean

install:
	pip install -e '.[dev]'

lint:
	ruff check .

test:
	pytest tests/

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache build/ dist/ *.egg-info/ .venv/
