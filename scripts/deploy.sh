#!/bin/bash

# IAM Activity Tracker Deployment Script
# This script builds and deploys the SAM application

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
S3_BUCKET="${S3_BUCKET:-}"

echo -e "${GREEN}IAM Activity Tracker - Deployment Script${NC}"
echo "========================================"

# Function to check if we're in a virtual environment
is_in_venv() {
    [[ -n "$VIRTUAL_ENV" ]] || [[ -n "$CONDA_DEFAULT_ENV" ]] || [[ "$VIRTUAL_ENV" != "" ]]
}

# Function to install tools in virtual environment
install_in_venv() {
    local tool=$1
    local package=$2
    
    echo -e "${YELLOW}Installing $tool in virtual environment...${NC}"
    if command -v pip &> /dev/null; then
        pip install "$package"
    elif command -v pip3 &> /dev/null; then
        pip3 install "$package"
    else
        echo -e "${RED}Error: pip not found in virtual environment${NC}"
        exit 1
    fi
}

# Check and install AWS CLI if needed
if ! command -v aws &> /dev/null; then
    if is_in_venv; then
        echo -e "${YELLOW}AWS CLI not found. Installing in virtual environment...${NC}"
        install_in_venv "AWS CLI" "awscli"
        echo -e "${GREEN}AWS CLI installed successfully!${NC}"
    else
        echo -e "${RED}Error: AWS CLI is not installed${NC}"
        echo -e "${YELLOW}Please install AWS CLI:${NC}"
        echo "  • Using pip: pip install awscli"
        echo "  • Or follow: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
        echo -e "${YELLOW}Then run the deployment again.${NC}"
        exit 1
    fi
fi

# Check and install SAM CLI if needed  
if ! command -v sam &> /dev/null; then
    if is_in_venv; then
        echo -e "${YELLOW}SAM CLI not found. Installing in virtual environment...${NC}"
        install_in_venv "SAM CLI" "aws-sam-cli"
        echo -e "${GREEN}SAM CLI installed successfully!${NC}"
    else
        echo -e "${RED}Error: SAM CLI is not installed${NC}"
        echo -e "${YELLOW}Please install SAM CLI:${NC}"
        echo "  • Using pip: pip install aws-sam-cli"
        echo "  • Or follow: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html"
        echo -e "${YELLOW}Then run the deployment again.${NC}"
        exit 1
    fi
fi

# Check AWS credentials
echo -e "${YELLOW}Checking AWS credentials...${NC}"
if ! aws sts get-caller-identity --profile "$AWS_PROFILE" &> /dev/null; then
    echo -e "${RED}Error: AWS credentials not configured for profile: $AWS_PROFILE${NC}"
    exit 1
fi

# Get S3 bucket for deployment artifacts if not provided
if [ -z "$S3_BUCKET" ]; then
    ACCOUNT_ID=$(aws sts get-caller-identity --profile "$AWS_PROFILE" --query Account --output text)
    S3_BUCKET="sam-deployments-${ACCOUNT_ID}-${REGION}"
    
    # Create S3 bucket if it doesn't exist
    if ! aws s3 ls "s3://${S3_BUCKET}" 2>/dev/null; then
        echo -e "${YELLOW}Creating S3 bucket for SAM deployments: ${S3_BUCKET}${NC}"
        if [ "$REGION" == "us-east-1" ]; then
            aws s3 mb "s3://${S3_BUCKET}"
        else
            aws s3 mb "s3://${S3_BUCKET}" --region "$REGION"
        fi
    else
        echo -e "${GREEN}Using existing S3 bucket: ${S3_BUCKET}${NC}"
    fi
fi

# Build the application
echo -e "${YELLOW}Building SAM application...${NC}"
sam build --use-container

# Deploy the application
echo -e "${YELLOW}Deploying SAM application...${NC}"

# Show deployment configuration if any custom parameters are set
if [ ! -z "$FILTERED_ROLES" ] || [ ! -z "$PROCESS_SSO_EVENTS" ] || [ ! -z "$ENABLE_ANALYTICS" ]; then
    echo -e "${GREEN}Deployment Configuration:${NC}"
    [ ! -z "$FILTERED_ROLES" ] && echo "  • Role Filtering: $FILTERED_ROLES"
    [ ! -z "$PROCESS_SSO_EVENTS" ] && echo "  • SSO Events: $PROCESS_SSO_EVENTS"
    [ ! -z "$SSO_REGION" ] && echo "  • SSO Region: $SSO_REGION"
    [ ! -z "$ENABLE_ANALYTICS" ] && echo "  • Analytics: $ENABLE_ANALYTICS"
    [ ! -z "$ENABLE_SECURITY_ALERTS" ] && echo "  • Security Alerts: $ENABLE_SECURITY_ALERTS"
    [ ! -z "$ALERTS_EMAIL_ADDRESS" ] && echo "  • Alert Email: $ALERTS_EMAIL_ADDRESS"
    [ ! -z "$SCHEDULE_EXPRESSION" ] && echo "  • Schedule: $SCHEDULE_EXPRESSION"
    [ ! -z "$MAX_WORKERS" ] && echo "  • Max Workers: $MAX_WORKERS"
    echo ""
fi

# Build parameter overrides from environment variables
PARAMETER_OVERRIDES=""
if [ ! -z "$PROCESS_SSO_EVENTS" ]; then
    PARAMETER_OVERRIDES="$PARAMETER_OVERRIDES ProcessSSOEvents=$PROCESS_SSO_EVENTS"
fi
if [ ! -z "$SSO_REGION" ]; then
    PARAMETER_OVERRIDES="$PARAMETER_OVERRIDES SSORegion=$SSO_REGION"
fi
if [ ! -z "$FILTERED_ROLES" ]; then
    PARAMETER_OVERRIDES="$PARAMETER_OVERRIDES FilteredRoles=\"$FILTERED_ROLES\""
fi
if [ ! -z "$ENABLE_ANALYTICS" ]; then
    PARAMETER_OVERRIDES="$PARAMETER_OVERRIDES EnableAnalytics=$ENABLE_ANALYTICS"
fi
if [ ! -z "$ENABLE_SECURITY_ALERTS" ]; then
    PARAMETER_OVERRIDES="$PARAMETER_OVERRIDES EnableSecurityAlerts=$ENABLE_SECURITY_ALERTS"
fi
if [ ! -z "$ALERTS_EMAIL_ADDRESS" ]; then
    PARAMETER_OVERRIDES="$PARAMETER_OVERRIDES AlertsEmailAddress=$ALERTS_EMAIL_ADDRESS"
fi
if [ ! -z "$SCHEDULE_EXPRESSION" ]; then
    PARAMETER_OVERRIDES="$PARAMETER_OVERRIDES ScheduleExpression=\"$SCHEDULE_EXPRESSION\""
fi
if [ ! -z "$MAX_WORKERS" ]; then
    PARAMETER_OVERRIDES="$PARAMETER_OVERRIDES MaxWorkers=$MAX_WORKERS"
fi

# Deploy with parameters if any are set
if [ ! -z "$PARAMETER_OVERRIDES" ]; then
    sam deploy \
        --stack-name "$STACK_NAME" \
        --s3-bucket "$S3_BUCKET" \
        --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
        --region "$REGION" \
        --parameter-overrides $PARAMETER_OVERRIDES \
        --no-fail-on-empty-changeset
else
    sam deploy \
        --stack-name "$STACK_NAME" \
        --s3-bucket "$S3_BUCKET" \
        --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
        --region "$REGION" \
        --no-fail-on-empty-changeset
fi

# Get stack outputs
echo -e "${GREEN}Deployment completed successfully!${NC}"
echo -e "${YELLOW}Stack outputs:${NC}"
aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --profile "$AWS_PROFILE" \
    --query 'Stacks[0].Outputs' \
    --output table

# Extract key outputs for post-deployment setup
ANALYTICS_ENABLED="${ENABLE_ANALYTICS:-true}"
if [ "$ANALYTICS_ENABLED" == "true" ]; then
    echo -e "${YELLOW}Getting deployment details...${NC}"
    
    OUTPUTS=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$REGION" \
        --profile "$AWS_PROFILE" \
        --query 'Stacks[0].Outputs' \
        --output json)
    
    ANALYTICS_BUCKET=$(echo "$OUTPUTS" | jq -r '.[] | select(.OutputKey=="AnalyticsBucketName") | .OutputValue // empty')
    GLUE_DATABASE=$(echo "$OUTPUTS" | jq -r '.[] | select(.OutputKey=="GlueDatabaseName") | .OutputValue // empty')
    ATHENA_WORKGROUP=$(echo "$OUTPUTS" | jq -r '.[] | select(.OutputKey=="AthenaWorkGroupName") | .OutputValue // empty')
fi

echo -e "${GREEN}IAM Activity Tracker is now deployed!${NC}"
echo ""

# Ask if user wants to run initialization
echo -e "${YELLOW}IMPORTANT: Initialize the system now?${NC}"
echo ""
echo "The initialization will:"
echo "  1. Collect up to 90 days of historical CloudTrail events"
echo "  2. Export data to S3 (if analytics enabled)"
echo "  3. Setup Athena tables automatically"
echo "  4. Make the system immediately ready for use"
echo ""
echo -e "${GREEN}Without initialization, you would need to wait:${NC}"
echo "  - 1 hour for first data collection"
echo "  - 24 hours for first S3 export"
echo ""

read -p "Run initialization now? (recommended) [Y/n]: " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    echo ""
    bash scripts/post-deploy-init.sh
else
    echo ""
    echo -e "${YELLOW}Skipping initialization. The system will start collecting data on schedule.${NC}"
    echo ""
    echo "System Schedule:"
    echo "  - Tracker Lambda: Runs ${SCHEDULE_EXPRESSION:-every hour}"
    if [ "$ANALYTICS_ENABLED" == "true" ]; then
        echo "  - Exporter Lambda: Runs ${EXPORT_SCHEDULE_EXPRESSION:-daily}"
        echo "  - Analytics: Enabled with S3 + Athena"
    else
        echo "  - Analytics: Disabled (DynamoDB only)"
    fi
    echo ""
    echo "To initialize manually later, run:"
    echo "  ${GREEN}make init${NC}"
    echo ""
fi

echo "Monitoring Commands:"
echo "  - CloudWatch Logs: ${GREEN}make logs${NC}"
echo "  - System Status: ${GREEN}make status${NC}"
echo "  - View Queries: ${GREEN}make list-queries${NC}"
echo ""

echo "Documentation:"
echo "  - README.md: Complete setup and usage guide"
echo "  - queries/: Pre-built analytics queries"
echo "  - Architecture.md: System design details"