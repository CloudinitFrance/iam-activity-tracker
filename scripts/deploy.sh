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

# Build parameter overrides from environment variables
PARAMETER_OVERRIDES=""
if [ ! -z "$PROCESS_SSO_EVENTS" ]; then
    PARAMETER_OVERRIDES="$PARAMETER_OVERRIDES ProcessSSOEvents=$PROCESS_SSO_EVENTS"
fi
if [ ! -z "$SSO_REGION" ]; then
    PARAMETER_OVERRIDES="$PARAMETER_OVERRIDES SSORegion=$SSO_REGION"
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

echo -e "${GREEN}IAM Activity Tracker is now running!${NC}"
echo ""
echo "System Status:"
echo "  • Tracker Lambda: Runs ${SCHEDULE_EXPRESSION:-every hour}"
if [ "$ANALYTICS_ENABLED" == "true" ]; then
    echo "  • Exporter Lambda: Runs ${EXPORT_SCHEDULE_EXPRESSION:-daily}"
    echo "  • Analytics: Enabled with S3 + Athena"
else
    echo "  • Analytics: Disabled (DynamoDB only)"
fi
echo ""

echo "Monitoring:"
echo "  • CloudWatch Logs: /aws/lambda/${STACK_NAME}-tracker"
if [ "$ANALYTICS_ENABLED" == "true" ]; then
    echo "  • Export Logs: /aws/lambda/${STACK_NAME}-exporter"
fi
echo "  • CloudWatch Alarms: Set up for function errors and high duration"
echo ""

if [ "$ANALYTICS_ENABLED" == "true" ] && [ ! -z "$ANALYTICS_BUCKET" ]; then
    echo "Analytics Setup:"
    echo "  • S3 Bucket: $ANALYTICS_BUCKET"
    echo "  • Glue Database: $GLUE_DATABASE"
    echo "  • Athena WorkGroup: $ATHENA_WORKGROUP"
    echo ""
    echo "Next Steps for Analytics:"
    echo "  1. Wait 24+ hours for initial data export"
    echo "  2. Run Glue Crawler to discover partitions:"
    echo "     aws glue start-crawler --name ${STACK_NAME}-crawler"
    echo ""
    echo "  3. Set up Athena table with query utilities:"
    echo "     cd queries/"
    echo "     python query_runner.py setup --s3-location s3://${ANALYTICS_BUCKET}/iam-events/"
    echo ""
    echo "  4. Run sample analytics queries:"
    echo "     python query_runner.py list"
    echo "     python query_runner.py run failed_auth"
    echo ""
fi

echo "Documentation:"
echo "  • README.md: Complete setup and usage guide"
echo "  • queries/: Pre-built analytics queries"
echo "  • Architecture.md: System design details"