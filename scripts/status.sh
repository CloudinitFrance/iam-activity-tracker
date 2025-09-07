#!/bin/bash

# IAM Activity Tracker Status Script
# Shows a clean, formatted status of the deployed stack

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

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}                    IAM Activity Tracker - Stack Status${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Check if stack exists
STACK_STATUS=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$AWS_REGION" \
    --profile "$AWS_PROFILE" \
    --query 'Stacks[0].StackStatus' \
    --output text 2>/dev/null) || STACK_STATUS=""

if [ -z "$STACK_STATUS" ]; then
    echo -e "${RED}✗ Stack '$STACK_NAME' not found${NC}"
    echo ""
    echo -e "${YELLOW}Available stacks in $AWS_REGION:${NC}"
    aws cloudformation list-stacks \
        --region "$AWS_REGION" \
        --profile "$AWS_PROFILE" \
        --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE \
        --query 'StackSummaries[*].{Name:StackName,Status:StackStatus,Created:CreationTime}' \
        --output table 2>/dev/null || echo -e "${RED}No stacks found${NC}"
    exit 1
fi

# Get stack info
LAST_UPDATED=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$AWS_REGION" \
    --profile "$AWS_PROFILE" \
    --query 'Stacks[0].LastUpdatedTime' \
    --output text 2>/dev/null)

echo -e "${YELLOW}Stack Information:${NC}"
echo "  Name:      $STACK_NAME"
echo "  Region:    $AWS_REGION"
echo "  Profile:   $AWS_PROFILE"
echo -e "  Status:    ${GREEN}$STACK_STATUS${NC}"
echo "  Updated:   $LAST_UPDATED"
echo ""

echo -e "${YELLOW}System Configuration:${NC}"
aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$AWS_REGION" \
    --profile "$AWS_PROFILE" \
    --query 'Stacks[0].Parameters[?ParameterKey==`ProcessIAMEvents`||ParameterKey==`ProcessSTSEvents`||ParameterKey==`ProcessSigninEvents`||ParameterKey==`EnableSecurityAlerts`||ParameterKey==`ScheduleExpression`||ParameterKey==`FilterAWSServiceEvents`].{Setting:ParameterKey,Value:ParameterValue}' \
    --output table

echo ""
echo -e "${YELLOW}Lambda Functions:${NC}"
aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$AWS_REGION" \
    --profile "$AWS_PROFILE" \
    --query 'Stacks[0].Outputs[?OutputKey==`TrackerFunctionArn`||OutputKey==`ExporterFunctionArn`].{Function:OutputKey,ARN:OutputValue}' \
    --output table

echo ""
echo -e "${YELLOW}Data Storage:${NC}"
aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$AWS_REGION" \
    --profile "$AWS_PROFILE" \
    --query 'Stacks[0].Outputs[?OutputKey==`EventsTableName`||OutputKey==`ControlTableName`||OutputKey==`AlertsTableName`||OutputKey==`AnalyticsBucketName`||OutputKey==`AthenaResultsBucketName`].{Component:OutputKey,Name:OutputValue}' \
    --output table

echo ""
echo -e "${YELLOW}Analytics & Alerts:${NC}"
aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$AWS_REGION" \
    --profile "$AWS_PROFILE" \
    --query 'Stacks[0].Outputs[?OutputKey==`GlueDatabaseName`||OutputKey==`AthenaWorkGroupName`||OutputKey==`SecurityAlertsTopicArn`||OutputKey==`SecurityAlertsEnabled`].{Service:OutputKey,Value:OutputValue}' \
    --output table

echo ""
echo -e "${YELLOW}Schedule Information:${NC}"
aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$AWS_REGION" \
    --profile "$AWS_PROFILE" \
    --query 'Stacks[0].Outputs[?OutputKey==`TrackerScheduleExpression`||OutputKey==`ExportScheduleExpression`].{Schedule:OutputKey,Frequency:OutputValue}' \
    --output table

echo ""