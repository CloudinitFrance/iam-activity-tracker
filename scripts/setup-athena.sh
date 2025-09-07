#!/bin/bash

# IAM Activity Tracker Athena Setup Script
# Initializes Athena tables for analytics

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
STACK_NAME="${STACK_NAME:-iam-activity-tracker}"
AWS_REGION="${AWS_REGION}"
AWS_PROFILE="${AWS_PROFILE}"

if [ -z "$AWS_REGION" ] || [ -z "$AWS_PROFILE" ]; then
    echo -e "${RED}Error: AWS_REGION and AWS_PROFILE environment variables must be set${NC}"
    exit 1
fi

echo -e "${YELLOW}Setting up Athena tables...${NC}"

# Get analytics bucket
ANALYTICS_BUCKET=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$AWS_REGION" \
    --profile "$AWS_PROFILE" \
    --query 'Stacks[0].Outputs[?OutputKey==`AnalyticsBucketName`].OutputValue' \
    --output text 2>/dev/null)

if [ -z "$ANALYTICS_BUCKET" ] || [ "$ANALYTICS_BUCKET" = "None" ]; then
    echo -e "${RED}Error: Could not find analytics bucket. Is the stack deployed with analytics enabled?${NC}"
    exit 1
fi

echo "Analytics Bucket: $ANALYTICS_BUCKET"

# Setup queries environment if not exists
cd queries
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Setting up query environment first...${NC}"
    bash setup.sh
fi

# Activate environment and run setup
source venv/bin/activate
python query_runner.py setup --s3-location "s3://$ANALYTICS_BUCKET/iam-events/"

echo -e "${GREEN}✓ Athena tables setup complete!${NC}"