# IAM Activity Tracker Makefile
#
# Supported Environment Variables for Deployment:
#   AWS_REGION              - AWS region for deployment (required)
#   AWS_PROFILE             - AWS profile to use (required)
#   STACK_NAME              - CloudFormation stack name (default: iam-activity-tracker)
#   FILTERED_ROLES          - Comma-separated role patterns to filter (e.g., "PrismaCloud*,Wiz*")
#   ENABLE_ANALYTICS        - Enable S3/Athena analytics (true/false, default: true)
#   ENABLE_SECURITY_ALERTS  - Enable SNS security alerts (true/false, default: true)
#   ALERTS_EMAIL_ADDRESS    - Email for security alerts (optional)
#   SCHEDULE_EXPRESSION     - Collection frequency (default: "rate(1 hour)")
#   MAX_WORKERS             - Max parallel threads (1-32, default: 16)
#   PROCESS_SSO_EVENTS      - Track SSO events (true/false, default: true)
#   SSO_REGION              - SSO instance region (default: us-east-1)

# Configuration from environment variables
STACK_NAME ?= iam-activity-tracker
AWS_REGION ?= $(shell echo $$AWS_REGION)
AWS_PROFILE ?= $(shell echo $$AWS_PROFILE)

# Check required environment variables
ifndef AWS_REGION
$(error AWS_REGION environment variable is not set. Set it with: export AWS_REGION=your-region)
endif
ifndef AWS_PROFILE
$(error AWS_PROFILE environment variable is not set. Set it with: export AWS_PROFILE=your-profile)
endif

# Colors
YELLOW = \033[1;33m
GREEN = \033[0;32m
RED = \033[0;31m
NC = \033[0m

.DEFAULT_GOAL := help

# Help
help: ## Show this help message
	@echo "$(YELLOW)IAM Activity Tracker - Makefile Commands$(NC)"
	@echo "========================================"
	@echo ""
	@echo "$(GREEN)Deployment Commands:$(NC)"
	@echo "  make deploy              Deploy the IAM Activity Tracker stack"
	@echo "  make destroy             Delete the stack and all resources"
	@echo "  make update              Update an existing deployment"
	@echo "  make status              Show stack status and configuration"
	@echo ""
	@echo "$(GREEN)Query Commands:$(NC)"
	@echo "  make list-queries        List all available pre-built queries"
	@echo "  make run-query Q=<name>  Run a specific query (e.g., Q=failed_auth)"
	@echo "  make setup-athena        Initialize Athena tables for analytics"
	@echo ""
	@echo "$(GREEN)Monitoring Commands:$(NC)"
	@echo "  make logs                View recent CloudWatch logs"
	@echo "  make logs-follow         Follow logs in real-time"
	@echo "  make test-alerts         Test the security alerting system"
	@echo ""
	@echo "$(GREEN)Development Commands:$(NC)"
	@echo "  make build               Build the SAM application"
	@echo "  make validate            Validate the CloudFormation template"
	@echo "  make clean               Clean build artifacts"
	@echo ""
	@echo "$(YELLOW)Required Environment Variables:$(NC)"
	@echo "  export AWS_REGION=your-region     (e.g., us-east-1, eu-west-1)"
	@echo "  export AWS_PROFILE=your-profile   (e.g., default, production)"
	@echo ""
	@echo "$(YELLOW)Examples:$(NC)"
	@echo "  export AWS_REGION=eu-west-1 AWS_PROFILE=production"
	@echo "  make deploy"
	@echo ""
	@echo "  # Deploy with SSO monitoring:"
	@echo "  export SSO_REGION=eu-west-1 PROCESS_SSO_EVENTS=true && make deploy"
	@echo ""
	@echo "  # Deploy with CSPM role filtering:"
	@echo "  export FILTERED_ROLES=\"PrismaCloud*,WizSecurityRole,*Scanner*\" && make deploy"
	@echo ""
	@echo "  # Deploy with multiple configurations:"
	@echo "  export FILTERED_ROLES=\"PrismaCloud*,Wiz*,*CSPM*\" \\"
	@echo "         ENABLE_ANALYTICS=true \\"
	@echo "         ALERTS_EMAIL_ADDRESS=\"security@example.com\" \\"
	@echo "         SCHEDULE_EXPRESSION=\"rate(6 hours)\" && make deploy"
	@echo ""
	@echo "  # Query examples:"
	@echo "  make run-query Q=root_usage"
	@echo "  make logs | grep ERROR"

# Prerequisites
check-aws:
	@which aws > /dev/null || (echo "$(RED)Error: AWS CLI is not installed$(NC)" && exit 1)

check-sam:
	@which sam > /dev/null || (echo "$(RED)Error: SAM CLI is not installed$(NC)" && exit 1)

check-prereqs: check-aws check-sam
	@aws sts get-caller-identity --profile $(AWS_PROFILE) > /dev/null || (echo "$(RED)Error: AWS credentials not configured$(NC)" && exit 1)

# Deployment
build: check-sam ## Build the SAM application
	@sam build --use-container

validate: check-sam ## Validate the CloudFormation template
	@bash scripts/validate.sh

deploy: ## Deploy the IAM Activity Tracker (auto-installs tools in venv)
	@bash scripts/deploy.sh

update: deploy ## Update an existing deployment

destroy: check-prereqs ## Delete all resources (WARNING: Deletes all data!)
	@echo "$(RED)WARNING: This will delete all resources including collected data!$(NC)"
	@read -p "Are you sure? Type 'yes' to confirm: " confirm && \
		if [ "$$confirm" = "yes" ]; then \
			SKIP_CONFIRM=true bash scripts/destroy.sh; \
		else \
			echo "Cancelled."; \
		fi

# Status and monitoring
status: check-aws ## Show current stack status and configuration
	@bash scripts/status.sh

logs: check-aws ## View recent CloudWatch logs
	@bash scripts/logs.sh

logs-follow: check-aws ## Follow logs in real-time
	@bash scripts/logs.sh follow

test-alerts: check-aws ## Test the security alerting system
	@bash scripts/test-alerts.sh

# Queries
list-queries: ## List all available pre-built queries
	@bash scripts/run-query.sh list

run-query: ## Run a specific query (use Q=query_name FORMAT=table|json)
ifndef Q
	@echo "$(RED)Error: Please specify a query name with Q=<name>$(NC)"
	@echo "Example: make run-query Q=failed_auth"
	@echo "         make run-query Q=sso_account_assignments FORMAT=json"
	@echo "Use 'make list-queries' to see available queries"
	@exit 1
else
	@bash scripts/run-query.sh $(Q) $(FORMAT)
endif

setup-athena: check-aws ## Initialize Athena tables for analytics
	@bash scripts/setup-athena.sh

# Utilities
clean: ## Remove build artifacts
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
	@rm -rf .aws-sam/
	@rm -rf functions/*/build/
	@rm -rf functions/*/__pycache__/
	@find . -type f -name "*.pyc" -delete
	@find . -type d -name "__pycache__" -delete
	@echo "$(GREEN)Clean complete!$(NC)"

# Shortcuts
d: deploy ## Shortcut for deploy
s: status ## Shortcut for status  
l: logs ## Shortcut for logs
q: list-queries ## Shortcut for list-queries

# Phony targets
.PHONY: help check-aws check-sam check-prereqs build validate deploy update destroy \
        status logs logs-follow test-alerts list-queries run-query setup-athena \
        clean d s l q
