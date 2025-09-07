#!/bin/bash

# IAM Activity Tracker Destroy Script
# This script removes the SAM application and all its resources

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
STACK_NAME="${STACK_NAME:-iam-activity-tracker}"
REGION="${AWS_REGION:-us-east-1}"
AWS_PROFILE="${AWS_PROFILE:-default}"

echo -e "${YELLOW}IAM Activity Tracker - Destroy Script${NC}"
echo "======================================"
echo -e "${RED}WARNING: This will delete all resources including DynamoDB tables with data!${NC}"
echo

# Skip confirmation if already confirmed (from Makefile)
if [ "$SKIP_CONFIRM" != "true" ]; then
    read -p "Are you sure you want to delete the stack '$STACK_NAME'? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        echo "Deletion cancelled."
        exit 0
    fi
fi

# Delete the stack
echo -e "${YELLOW}Deleting CloudFormation stack: $STACK_NAME${NC}"
aws cloudformation delete-stack \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --profile "$AWS_PROFILE"

# Wait for deletion to complete
echo -e "${YELLOW}Waiting for stack deletion to complete...${NC}"
aws cloudformation wait stack-delete-complete \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --profile "$AWS_PROFILE"

echo -e "${GREEN}Stack '$STACK_NAME' has been successfully deleted.${NC}"