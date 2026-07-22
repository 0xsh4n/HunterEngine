.PHONY: install install-dev lint typecheck test scan crawl check-tools dashboard ai-health docker-up clean help

# ── Setup ─────────────────────────────────────────────────────────────────

install:                         ## Install core dependencies
	pip install -e .

install-dev:                     ## Install with dev dependencies
	pip install -e ".[dev]"
	playwright install chromium

# ── Quality ───────────────────────────────────────────────────────────────

lint:                            ## Run flake8 linter
	python -m flake8 . --max-line-length 120

typecheck:                       ## Run mypy type checker
	python -m mypy . --ignore-missing-imports

test:                            ## Run test suite
	python -m pytest tests/ -v

# ── Run ───────────────────────────────────────────────────────────────────

scan:                            ## Run full scan pipeline
	python main.py scan

crawl:                           ## Run standalone auto-crawl (set TARGET env var)
	python main.py crawl $(TARGET)

check-tools:                     ## Check installed external tools
	python main.py check-tools

ai-health:                       ## Probe external Ollama / configured model
	python main.py ai-health

dashboard:                       ## Web config UI + health check button
	python main.py dashboard

docker-up:                       ## Build/run app container (Ollama on host)
	docker compose up -d --build

# ── Housekeeping ──────────────────────────────────────────────────────────

clean:                           ## Remove build artifacts and caches
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ *.egg-info/

help:                            ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
