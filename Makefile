.PHONY: setup test lint format install-hayabusa check-hayabusa install-deps build-index mappings

HAYABUSA_LOCAL := ./hayabusa/hayabusa

setup: install-deps check-hayabusa build-index
	@echo "==> Setup complete. Run 'make test' to verify."

install-deps:
	uv sync --extra dev

check-hayabusa:
	@if command -v hayabusa >/dev/null 2>&1; then \
		echo "==> Hayabusa found on PATH:"; \
		hayabusa help 2>&1 | head -1; \
	elif [ -f "$(HAYABUSA_LOCAL)" ]; then \
		echo "==> Hayabusa found at $(HAYABUSA_LOCAL):"; \
		$(HAYABUSA_LOCAL) help 2>&1 | head -1; \
	else \
		echo "==> Hayabusa not found — installing..."; \
		$(MAKE) install-hayabusa; \
	fi

install-hayabusa:
	./scripts/install_hayabusa.sh

# Parse every Sigma rule into .cache/rule_index.json. Slow (~2-3 min for the
# bundled corpus on WSL2 /mnt/c) but done once — the server reads the cache.
# Re-run after 'update_rules' changes the corpus; edits to rules/ need nothing.
build-index:
	@echo "==> Building rule index (this takes a few minutes)..."
	@uv run python -c "from mcp_hayabusa import kb; i = kb.load_index(rebuild=True); \
	print(f'==> Indexed {len(i.rules)} rules'); [print('   ', n) for n in i.notes]"

# Regenerate mappings/attack.yaml from MITRE's ATT&CK STIX bundle (~53MB
# download). The generated file is committed; the server never fetches at runtime.
mappings:
	uv run python scripts/build_attack_mappings.py

test:
	uv run pytest

lint:
	uv run ruff check .
	uv run ruff format --check .

format:
	uv run ruff format .
	uv run ruff check --fix .
