.PHONY: check format install-macos-agent lint pre-commit test typecheck uninstall-macos-agent

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

install-macos-agent:
	python3 scripts/macos/install_launch_agent.py

uninstall-macos-agent:
	python3 scripts/macos/install_launch_agent.py --uninstall
