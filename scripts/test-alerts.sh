#!/bin/bash

# IAM Activity Tracker Test Alerts Script
# Sends a test alert to verify SNS configuration

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

echo -e "${YELLOW}Testing alert system...${NC}"

# Get SNS Topic ARN
SNS_TOPIC=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$AWS_REGION" \
    --profile "$AWS_PROFILE" \
    --query 'Stacks[0].Outputs[?OutputKey==`SecurityAlertsTopicArn`].OutputValue' \
    --output text 2>/dev/null)

if [ -z "$SNS_TOPIC" ] || [ "$SNS_TOPIC" = "None" ]; then
    echo -e "${RED}Error: Alerts not enabled or topic not found${NC}"
    echo "Ensure EnableSecurityAlerts=true when deploying"
    exit 1
fi

echo "SNS Topic: $SNS_TOPIC"

# Send test alert
aws sns publish \
    --topic-arn "$SNS_TOPIC" \
    --subject "[TEST] IAM Activity Tracker Alert Test" \
    --message "This is a test alert from IAM Activity Tracker. If you received this, your alerts are working correctly!" \
    --region "$AWS_REGION" \
    --profile "$AWS_PROFILE"

echo -e "${GREEN}✓ Test alert sent successfully!${NC}"
echo "Check your email/SMS for the test notification."