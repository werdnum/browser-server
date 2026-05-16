.PHONY: check format lint pre-commit test typecheck

lint:
	.venv/bin/ruff check .
	.venv/bin/ruff format --check .

format:
	.venv/bin/ruff check --fix .
	.venv/bin/ruff format .

typecheck:
	.venv/bin/ty check

test:
	REQUIRE_NOVNC=1 .venv/bin/python -m pytest -q
	npm run test:user

check: lint typecheck test

pre-commit:
	.venv/bin/pre-commit run --all-files
