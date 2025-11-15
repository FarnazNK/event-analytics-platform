# Makefile for Event Analytics Platform
# Provides convenient commands for development, testing, and deployment

.PHONY: help install dev test lint format security docker clean all

# Default target
.DEFAULT_GOAL := help

# Colors for output
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(BLUE)Event Analytics Platform - Development Commands$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

# ====================================
# Installation
# ====================================

install: ## Install production dependencies
	@echo "$(BLUE)Installing production dependencies...$(NC)"
	pip install --upgrade pip setuptools wheel
	pip install -r requirements.txt
	@echo "$(GREEN)✓ Dependencies installed$(NC)"

dev: ## Install development dependencies
	@echo "$(BLUE)Installing development dependencies...$(NC)"
	pip install --upgrade pip setuptools wheel
	pip install -r requirements.txt
	pip install pytest pytest-asyncio pytest-cov pytest-mock black flake8 pylint mypy isort bandit safety ipython
	@echo "$(GREEN)✓ Development environment ready$(NC)"

# ====================================
# Environment Setup
# ====================================

env: ## Create .env file from example
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "$(YELLOW)⚠ Created .env file from example$(NC)"; \
		echo "$(YELLOW)⚠ Please update with your configuration!$(NC)"; \
		echo "$(YELLOW)⚠ Generate SECRET_KEY with: make generate-secret$(NC)"; \
	else \
		echo "$(GREEN)✓ .env file already exists$(NC)"; \
	fi

generate-secret: ## Generate a new SECRET_KEY
	@echo "$(BLUE)Generated SECRET_KEY:$(NC)"
	@openssl rand -hex 32

# ====================================
# Database
# ====================================

db-init: ## Initialize database
	@echo "$(BLUE)Initializing database...$(NC)"
	python scripts/init_db.py
	@echo "$(GREEN)✓ Database initialized$(NC)"

db-migrate: ## Run database migrations
	@echo "$(BLUE)Running migrations...$(NC)"
	alembic upgrade head
	@echo "$(GREEN)✓ Migrations complete$(NC)"

db-reset: ## Reset database (⚠️ DESTRUCTIVE)
	@echo "$(RED)⚠ This will delete all data!$(NC)"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		echo "$(BLUE)Resetting database...$(NC)"; \
		python scripts/reset_db.py; \
		echo "$(GREEN)✓ Database reset$(NC)"; \
	fi

# ====================================
# Development Server
# ====================================

run: ## Run development server
	@echo "$(BLUE)Starting development server...$(NC)"
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

run-prod: ## Run production server
	@echo "$(BLUE)Starting production server...$(NC)"
	gunicorn app.main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000

# ====================================
# Testing
# ====================================

test: ## Run all tests
	@echo "$(BLUE)Running tests...$(NC)"
	pytest tests/ -v
	@echo "$(GREEN)✓ Tests passed$(NC)"

test-unit: ## Run unit tests only
	@echo "$(BLUE)Running unit tests...$(NC)"
	pytest tests/unit/ -v

test-integration: ## Run integration tests only
	@echo "$(BLUE)Running integration tests...$(NC)"
	pytest tests/integration/ -v

test-security: ## Run security tests only
	@echo "$(BLUE)Running security tests...$(NC)"
	pytest tests/security/ -v

test-cov: ## Run tests with coverage
	@echo "$(BLUE)Running tests with coverage...$(NC)"
	pytest tests/ --cov=app --cov-report=html --cov-report=term-missing
	@echo "$(GREEN)✓ Coverage report generated in htmlcov/$(NC)"

test-watch: ## Run tests in watch mode
	@echo "$(BLUE)Running tests in watch mode...$(NC)"
	pytest-watch

# ====================================
# Code Quality
# ====================================

lint: ## Run all linters
	@echo "$(BLUE)Running linters...$(NC)"
	@$(MAKE) lint-flake8
	@$(MAKE) lint-pylint
	@$(MAKE) lint-mypy
	@echo "$(GREEN)✓ Linting complete$(NC)"

lint-flake8: ## Run flake8
	@echo "$(BLUE)Running flake8...$(NC)"
	flake8 app/ tests/

lint-pylint: ## Run pylint
	@echo "$(BLUE)Running pylint...$(NC)"
	pylint app/

lint-mypy: ## Run mypy
	@echo "$(BLUE)Running mypy...$(NC)"
	mypy app/ --ignore-missing-imports

format: ## Format code with black and isort
	@echo "$(BLUE)Formatting code...$(NC)"
	black app/ tests/
	isort app/ tests/
	@echo "$(GREEN)✓ Code formatted$(NC)"

format-check: ## Check code formatting
	@echo "$(BLUE)Checking code formatting...$(NC)"
	black --check app/ tests/
	isort --check-only app/ tests/

# ====================================
# Security
# ====================================

security: ## Run all security checks
	@echo "$(BLUE)Running security checks...$(NC)"
	@$(MAKE) security-bandit
	@$(MAKE) security-safety
	@echo "$(GREEN)✓ Security checks complete$(NC)"

security-bandit: ## Run Bandit security linter
	@echo "$(BLUE)Running Bandit...$(NC)"
	bandit -r app/ -f json -o bandit-report.json
	bandit -r app/

security-safety: ## Check for vulnerable dependencies
	@echo "$(BLUE)Checking for vulnerable dependencies...$(NC)"
	safety check

security-audit: ## Full security audit
	@echo "$(BLUE)Running full security audit...$(NC)"
	@$(MAKE) security
	@$(MAKE) test-security
	@echo "$(GREEN)✓ Security audit complete$(NC)"

# ====================================
# Docker
# ====================================

docker-build: ## Build Docker image
	@echo "$(BLUE)Building Docker image...$(NC)"
	docker build -t event-analytics-platform:latest -f docker/Dockerfile .
	@echo "$(GREEN)✓ Docker image built$(NC)"

docker-up: ## Start Docker Compose services
	@echo "$(BLUE)Starting services...$(NC)"
	docker-compose up -d
	@echo "$(GREEN)✓ Services started$(NC)"
	@echo "$(YELLOW)API: http://localhost:8000$(NC)"
	@echo "$(YELLOW)Docs: http://localhost:8000/docs$(NC)"

docker-down: ## Stop Docker Compose services
	@echo "$(BLUE)Stopping services...$(NC)"
	docker-compose down
	@echo "$(GREEN)✓ Services stopped$(NC)"

docker-logs: ## View Docker Compose logs
	docker-compose logs -f

docker-clean: ## Clean Docker resources
	@echo "$(RED)Cleaning Docker resources...$(NC)"
	docker-compose down -v
	docker system prune -f
	@echo "$(GREEN)✓ Docker resources cleaned$(NC)"

# ====================================
# Cleanup
# ====================================

clean: ## Clean cache and temporary files
	@echo "$(BLUE)Cleaning cache and temporary files...$(NC)"
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.log" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name ".coverage" -delete
	find . -type f -name "coverage.xml" -delete
	rm -rf build/ dist/
	@echo "$(GREEN)✓ Cleanup complete$(NC)"

clean-all: clean docker-clean ## Deep clean including Docker

# ====================================
# CI/CD Simulation
# ====================================

ci: ## Simulate CI pipeline locally
	@echo "$(BLUE)Running CI pipeline locally...$(NC)"
	@$(MAKE) format-check
	@$(MAKE) lint
	@$(MAKE) security
	@$(MAKE) test-cov
	@echo "$(GREEN)✓ CI pipeline passed$(NC)"

# ====================================
# Documentation
# ====================================

docs: ## Generate documentation
	@echo "$(BLUE)Generating documentation...$(NC)"
	mkdocs build
	@echo "$(GREEN)✓ Documentation generated in site/$(NC)"

docs-serve: ## Serve documentation locally
	@echo "$(BLUE)Serving documentation...$(NC)"
	mkdocs serve

# ====================================
# Utilities
# ====================================

check-env: ## Check environment configuration
	@echo "$(BLUE)Checking environment configuration...$(NC)"
	@if [ -f .env ]; then \
		echo "$(GREEN)✓ .env file exists$(NC)"; \
		if grep -q "CHANGE_ME" .env; then \
			echo "$(RED)✗ WARNING: Default values found in .env$(NC)"; \
			echo "$(YELLOW)  Please update SECRET_KEY and passwords!$(NC)"; \
		else \
			echo "$(GREEN)✓ No default values found$(NC)"; \
		fi \
	else \
		echo "$(RED)✗ .env file not found$(NC)"; \
		echo "$(YELLOW)  Run: make env$(NC)"; \
	fi

check-deps: ## Check for outdated dependencies
	@echo "$(BLUE)Checking for outdated dependencies...$(NC)"
	pip list --outdated

update-deps: ## Update dependencies (⚠️ use with caution)
	@echo "$(YELLOW)⚠ This will update all dependencies$(NC)"
	@read -p "Continue? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		pip install --upgrade -r requirements.txt; \
		pip freeze > requirements.txt; \
		echo "$(GREEN)✓ Dependencies updated$(NC)"; \
		echo "$(YELLOW)⚠ Please test thoroughly!$(NC)"; \
	fi

# ====================================
# All-in-one Commands
# ====================================

setup: dev env ## Complete development setup
	@echo "$(GREEN)✓ Development environment ready!$(NC)"
	@echo "$(YELLOW)Next steps:$(NC)"
	@echo "  1. Update .env with your configuration"
	@echo "  2. Run: make db-init"
	@echo "  3. Run: make run"

all: format lint security test ## Run all quality checks

pre-commit: format lint test-cov ## Run before committing
	@echo "$(GREEN)✓ Ready to commit!$(NC)"
