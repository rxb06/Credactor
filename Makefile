.PHONY: help install dev test lint scan scan-dry clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install the package
	pip install .

dev: ## Install with dev dependencies
	pip install -e ".[dev,encoding]"

test: ## Run tests
	python -m pytest tests/ -v

lint: ## Run linter
	ruff check credredactor/ tests/

scan: ## Run credredactor on the project
	python -m credredactor --dry-run .

scan-fix: ## Run credredactor and fix all findings
	python -m credredactor --fix-all .

clean: ## Remove build artifacts
	rm -rf build/ dist/ *.egg-info .pytest_cache .ruff_cache __pycache__
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	find . -name "*.bak" -delete 2>/dev/null || true
