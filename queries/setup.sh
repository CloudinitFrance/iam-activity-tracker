#!/bin/bash

# Query Utilities Setup Script
# Sets up Python environment for running analytics queries

set -e

echo "Setting up IAM Activity Analytics Query Utilities"
echo "=================================================="

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install requirements
echo "Installing Python dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

echo ""
echo "Setup completed successfully!"
echo ""
echo "Quick Start:"
echo "  1. Activate environment: source venv/bin/activate"
echo "  2. List available queries: python query_runner.py list"
echo "  3. Set up Athena table: python query_runner.py setup --s3-location s3://YOUR-BUCKET/iam-events/"
echo "  4. Run a query: python query_runner.py run failed_auth"
echo ""
echo "Environment Variables Setup:"

# Get CloudFormation stack outputs
STACK_NAME="iam-activity-tracker"
AWS_REGION="${AWS_REGION:-eu-west-1}"

echo "Fetching stack outputs from CloudFormation..."

if command -v aws &> /dev/null; then
    # Try to get actual values from CloudFormation
    ATHENA_DATABASE=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$AWS_REGION" --query 'Stacks[0].Outputs[?OutputKey==`GlueDatabaseName`].OutputValue' --output text 2>/dev/null || echo "")
    ATHENA_WORKGROUP=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$AWS_REGION" --query 'Stacks[0].Outputs[?OutputKey==`AthenaWorkGroupName`].OutputValue' --output text 2>/dev/null || echo "")
    ATHENA_RESULTS_BUCKET=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$AWS_REGION" --query 'Stacks[0].Outputs[?OutputKey==`AthenaResultsBucketName`].OutputValue' --output text 2>/dev/null || echo "")
    ANALYTICS_BUCKET=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$AWS_REGION" --query 'Stacks[0].Outputs[?OutputKey==`AnalyticsBucketName`].OutputValue' --output text 2>/dev/null || echo "")
    
    if [ -n "$ATHENA_DATABASE" ] && [ "$ATHENA_DATABASE" != "None" ]; then
        echo ""
        echo "Found stack outputs! Copy these environment variables:"
        echo "  export ATHENA_DATABASE='$ATHENA_DATABASE'"
        echo "  export ATHENA_WORKGROUP='$ATHENA_WORKGROUP'"
        echo "  export ATHENA_OUTPUT_LOCATION='s3://$ATHENA_RESULTS_BUCKET/'"
        echo ""
        echo "Data location for setup:"
        echo "  python query_runner.py setup --s3-location s3://$ANALYTICS_BUCKET/iam-events/"
    else
        echo ""
        echo "WARNING: Stack not found or outputs not available. Using account ID from STS:"
        ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null)
        if [ -n "$ACCOUNT_ID" ]; then
            echo "  export ATHENA_DATABASE='iam_activity_tracker_database'"
            echo "  export ATHENA_WORKGROUP='iam-activity-tracker-workgroup'"
            echo "  export ATHENA_OUTPUT_LOCATION='s3://iam-activity-tracker-athena-results-$ACCOUNT_ID/'"
            echo ""
            echo "Data location for setup:"
            echo "  python query_runner.py setup --s3-location s3://iam-activity-tracker-analytics-$ACCOUNT_ID/iam-events/"
        else
            echo "  ERROR: Cannot get account ID. Check AWS credentials."
        fi
    fi
else
    echo ""
    echo "WARNING: AWS CLI not found. Install AWS CLI and configure credentials."
fi