.PHONY: setup test lint format install-hayabusa check-hayabusa install-deps build-index mappings \
        mongo-up mongo-down mongo-shell mongo-stats load-mongo load-atlas load-owasp \
        atlas-bundle diff-versions coverage-all

HAYABUSA_LOCAL := ./hayabusa/hayabusa

# MongoDB backing store. 8.0 is MongoDB's current production (LTS) release
# series; bare 'mongo:8' resolves to 8.3, a rapid release superseded every
# quarter. Pinning the LTS line keeps a rebuilt container on the same wire
# protocol and aggregation semantics the tests were written against.
MONGO_IMAGE   ?= mongo:8.0
MONGO_NAME    ?= hayabusa-mongo
MONGO_PORT    ?= 27017
MONGO_VOLUME  ?= hayabusa-mongo-data
MONGO_DB      ?= hayabusa

# Two adjacent ATT&CK releases to diff. Override on the command line:
#   make diff-versions OLD=17.1 NEW=18.1
OLD ?= 18.1
NEW ?= 19.2

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

# --------------------------------------------------------------------------
# MongoDB backing store
# --------------------------------------------------------------------------

# Named volume, not an anonymous one: without -v, 'docker rm' destroys the
# database. With it, the data survives and reattaches to a recreated container.
mongo-up:
	@if [ -n "$$(docker ps -aq -f name=^/$(MONGO_NAME)$$)" ]; then \
		docker start $(MONGO_NAME) >/dev/null && echo "==> $(MONGO_NAME) started"; \
	else \
		docker run -d --name $(MONGO_NAME) -p $(MONGO_PORT):27017 \
			-v $(MONGO_VOLUME):/data/db $(MONGO_IMAGE) >/dev/null && \
		echo "==> $(MONGO_NAME) created from $(MONGO_IMAGE)"; \
	fi
	@for i in $$(seq 1 30); do \
		docker exec $(MONGO_NAME) mongosh --quiet --eval "db.runCommand({ping:1}).ok" \
			>/dev/null 2>&1 && break; \
		sleep 1; \
	done
	@docker exec $(MONGO_NAME) mongosh --quiet --eval \
		'print("==> MongoDB " + db.version() + " ready on port $(MONGO_PORT)")'

# Stops the container; the named volume (and so the data) is untouched.
mongo-down:
	@docker stop $(MONGO_NAME) >/dev/null 2>&1 && echo "==> $(MONGO_NAME) stopped" \
		|| echo "==> $(MONGO_NAME) not running"

mongo-shell:
	docker exec -it $(MONGO_NAME) mongosh $(MONGO_DB)

# Ingest the rule index + ATT&CK mappings. Needs 'make build-index' and
# 'make mappings' to have run; reads only local files, never the network.
load-mongo:
	uv run python scripts/load_mongo.py

load-atlas:
	uv run python scripts/build_atlas_mappings.py --load

load-owasp:
	uv run python scripts/load_owasp.py

# Regenerate the combined ATLAS + ATT&CK STIX bundle from mitre-atlas/atlas-data.
atlas-bundle:
	./scripts/fetch_atlas_bundle.sh

# Compare two ATT&CK releases and report which Sigma rules the changes affect.
diff-versions:
	uv run python scripts/diff_frameworks.py --old $(OLD) --new $(NEW) --ingest

# Coverage across every ingested framework in a single aggregation — the query
# the shared attack_techniques collection exists for.
coverage-all:
	@uv run python -c "from mcp_hayabusa import mongo; db = mongo.connect(); \
	r = mongo.all_frameworks_coverage(db); \
	[print(f\"{n:<22} {f['framework_version']:<9} \
{f['entries_covered']:>4}/{f['entries_total']:<5} covered  {f['entries_gap']:>4} gaps\") \
	  for n, f in r['frameworks'].items()]; \
	print(f\"{'TOTAL':<22} {'':<9} {r['entries_covered']:>4}/{r['entries_total']:<5} covered  \
{r['entries_gap']:>4} gaps\")"

mongo-stats:
	@uv run python -c "import json; from mcp_hayabusa import mongo; \
	db = mongo.connect(); print(json.dumps(mongo.stats(db), indent=2))"
