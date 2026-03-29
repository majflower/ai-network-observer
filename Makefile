.PHONY: help install test docker-build docker-run clean lint format

# Variables
PYTHON := python3
PIP := pip3
DOCKER := docker
DOCKER_COMPOSE := docker-compose
IMAGE_NAME := ai-network-observer
CONTAINER_NAME := network-observer

help: ## Show this help message
	@echo "AI Network Observer - Available Commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies
	$(PIP) install -r requirements.txt
	$(PIP) install -r requirements-dev.txt

install-dev: ## Install development dependencies
	$(PIP) install -r requirements-dev.txt

test: ## Run tests
	pytest tests/ -v --cov=src --cov-report=html --cov-report=term

test-fast: ## Run fast tests only
	pytest tests/ -v -m "not slow"

lint: ## Run code linters
	flake8 src/ tests/
	pylint src/
	mypy src/

format: ## Format code with black
	black src/ tests/ examples/
	isort src/ tests/ examples/

docker-build: ## Build Docker image
	$(DOCKER) build -t $(IMAGE_NAME):latest .

docker-run: ## Run Docker container
	$(DOCKER_COMPOSE) up -d

docker-run-full: ## Run with all services (Neo4j, Elasticsearch, Grafana)
	$(DOCKER_COMPOSE) --profile full up -d

docker-stop: ## Stop Docker containers
	$(DOCKER_COMPOSE) down

docker-logs: ## View Docker logs
	$(DOCKER_COMPOSE) logs -f observer

docker-shell: ## Open shell in container
	$(DOCKER) exec -it $(CONTAINER_NAME) /bin/bash

demo: ## Run interactive demo
	$(PYTHON) examples/demo.py

run-basic: ## Run basic capture (no Docker)
	sudo $(PYTHON) src/main.py -i eth0 --duration 5

run-ai: ## Run with AI analysis (requires API key)
	sudo $(PYTHON) src/main.py -i eth0 --enable-llm --duration 10

clean: ## Clean temporary files
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.log" -delete
	rm -rf .pytest_cache .coverage htmlcov/ .mypy_cache/
	rm -rf build/ dist/ *.egg-info/

clean-all: clean ## Clean everything including output
	rm -rf output/ logs/ network_logs/
	$(DOCKER_COMPOSE) down -v

setup-dev: install-dev ## Setup development environment
	pre-commit install
	cp .env.example .env
	@echo "✓ Development environment setup complete"
	@echo "  Edit .env file with your configuration"

docs: ## Generate documentation
	cd docs && make html

docker-push: ## Push Docker image to registry
	$(DOCKER) tag $(IMAGE_NAME):latest your-registry/$(IMAGE_NAME):latest
	$(DOCKER) push your-registry/$(IMAGE_NAME):latest

deploy: ## Deploy to production (placeholder)
	@echo "Production deployment not implemented"
	@echo "Use: docker-compose -f docker-compose.prod.yml up -d"

benchmark: ## Run performance benchmarks
	$(PYTHON) tests/benchmarks/run_benchmarks.py

security-scan: ## Scan for security vulnerabilities
	bandit -r src/
	safety check

all: clean install lint test ## Run all checks

.DEFAULT_GOAL := help
