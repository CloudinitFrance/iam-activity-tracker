#!/bin/bash

# IAM Activity Tracker Query Runner Script
# Runs pre-built analytics queries

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
QUERY_NAME="$1"
FORMAT="${2:-table}"
ACTION="${3:-run}"

# Check if first arg is "list"
if [ "$QUERY_NAME" = "list" ]; then
    ACTION="list"
    QUERY_NAME=""
fi

if [ -z "$QUERY_NAME" ] && [ "$ACTION" != "list" ]; then
    echo -e "${RED}Error: Please specify a query name${NC}"
    echo "Usage: $0 <query_name> [format]"
    echo "   or: $0 list"
    echo ""
    echo "Format options: table (default), json"
    echo ""
    echo "Examples:"
    echo "  $0 failed_auth"
    echo "  $0 root_usage json" 
    echo "  $0 sso_account_assignments table"
    echo "  $0 list"
    exit 1
fi

# Setup queries environment if not exists
cd queries
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Setting up query environment...${NC}"
    bash setup.sh
else
    echo -e "${GREEN}Query environment ready${NC}"
fi

# Activate environment
source venv/bin/activate

if [ "$ACTION" = "list" ] || [ "$QUERY_NAME" = "list" ]; then
    echo -e "${YELLOW}Available Queries:${NC}"
    python query_runner.py list
else
    python query_runner.py run "$QUERY_NAME" --format "$FORMAT"
fi