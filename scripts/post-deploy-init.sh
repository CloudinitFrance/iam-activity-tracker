#!/bin/bash

# Post-Deployment Initialization Script
# Runs initial data collection and sets up analytics immediately after deployment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration from environment
STACK_NAME="${STACK_NAME:-iam-activity-tracker}"
REGION="${AWS_REGION:-us-east-1}"
AWS_PROFILE="${AWS_PROFILE:-default}"

echo -e "${BLUE}================================================================${NC}"
echo -e "${GREEN}    IAM Activity Tracker - Post-Deployment Initialization${NC}"
echo -e "${BLUE}================================================================${NC}"
echo ""

# Function to show spinner
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while ps -p $pid > /dev/null 2>&1; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\r"
    done
    printf "    \r"
}

# Get Lambda function names from stack outputs
echo -e "${YELLOW}Getting deployment information...${NC}"
TRACKER_FUNCTION=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --profile "$AWS_PROFILE" \
    --query 'Stacks[0].Outputs[?OutputKey==`TrackerFunctionArn`].OutputValue' \
    --output text | sed 's/.*:function://')

ANALYTICS_ENABLED=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --profile "$AWS_PROFILE" \
    --query 'Stacks[0].Parameters[?ParameterKey==`EnableAnalytics`].ParameterValue' \
    --output text)

if [ "$ANALYTICS_ENABLED" == "true" ]; then
    EXPORTER_FUNCTION=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$REGION" \
        --profile "$AWS_PROFILE" \
        --query 'Stacks[0].Outputs[?OutputKey==`ExporterFunctionArn`].OutputValue' \
        --output text | sed 's/.*:function://')
    
    ANALYTICS_BUCKET=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$REGION" \
        --profile "$AWS_PROFILE" \
        --query 'Stacks[0].Outputs[?OutputKey==`AnalyticsBucketName`].OutputValue' \
        --output text)
fi

echo -e "${GREEN}Stack information retrieved successfully${NC}"
echo ""

# Step 1: Initial tracker run (collect last 90 days of data)
echo -e "${YELLOW}Step 1: Running initial CloudTrail event collection...${NC}"
echo -e "   This will collect up to 90 days of historical IAM/STS/Signin events"
echo -e "   This may take 1-5 minutes depending on your account activity..."

# Invoke tracker Lambda synchronously
(
    aws lambda invoke \
        --function-name "$TRACKER_FUNCTION" \
        --region "$REGION" \
        --profile "$AWS_PROFILE" \
        --invocation-type RequestResponse \
        --payload '{"source": "post-deploy-init"}' \
        /tmp/tracker-response.json > /dev/null 2>&1
) &
TRACKER_PID=$!

# Show spinner while waiting
spinner $TRACKER_PID
wait $TRACKER_PID

# Check if successful
if [ $? -eq 0 ]; then
    EVENTS_PROCESSED=$(cat /tmp/tracker-response.json | jq -r '.body.total_events_processed // 0')
    EVENTS_FILTERED=$(cat /tmp/tracker-response.json | jq -r '.body.total_events_filtered // 0')
    echo -e "${GREEN}Initial data collection complete!${NC}"
    echo -e "   - Events collected: ${GREEN}$EVENTS_PROCESSED${NC}"
    if [ "$EVENTS_FILTERED" -gt 0 ]; then
        echo -e "   - Events filtered: ${YELLOW}$EVENTS_FILTERED${NC}"
    fi
else
    echo -e "${RED}Initial data collection failed${NC}"
    echo "  Check CloudWatch logs: /aws/lambda/${STACK_NAME}-tracker"
    exit 1
fi
echo ""

# Step 2: Initial export run (if analytics enabled)
if [ "$ANALYTICS_ENABLED" == "true" ]; then
    echo -e "${YELLOW}Step 2: Running initial export to S3...${NC}"
    echo -e "   Converting DynamoDB data to Parquet format in S3"
    echo -e "   This may take 1-3 minutes..."
    
    # Invoke exporter Lambda synchronously
    (
        aws lambda invoke \
            --function-name "$EXPORTER_FUNCTION" \
            --region "$REGION" \
            --profile "$AWS_PROFILE" \
            --invocation-type RequestResponse \
            --payload '{"source": "post-deploy-init"}' \
            /tmp/exporter-response.json > /dev/null 2>&1
    ) &
    EXPORTER_PID=$!
    
    # Show spinner while waiting
    spinner $EXPORTER_PID
    wait $EXPORTER_PID
    
    if [ $? -eq 0 ]; then
        EXPORT_STATUS=$(cat /tmp/exporter-response.json | jq -r '.statusCode // 500')
        if [ "$EXPORT_STATUS" == "200" ]; then
            echo -e "${GREEN}Initial export complete!${NC}"
            
            # Check S3 for files
            FILE_COUNT=$(aws s3 ls s3://${ANALYTICS_BUCKET}/iam-events/ --recursive --profile "$AWS_PROFILE" | wc -l)
            echo -e "   - Files exported to S3: ${GREEN}$FILE_COUNT${NC}"
        else
            echo -e "${YELLOW}Export completed with warnings${NC}"
            echo "  Check CloudWatch logs: /aws/lambda/${STACK_NAME}-exporter"
        fi
    else
        echo -e "${RED}Initial export failed${NC}"
        echo "  Check CloudWatch logs: /aws/lambda/${STACK_NAME}-exporter"
    fi
    echo ""
    
    # Step 3: Setup Athena tables
    echo -e "${YELLOW}Step 3: Setting up Athena tables...${NC}"
    
    # Run the setup-athena script with correct environment variables
    if [ -f "scripts/setup-athena.sh" ]; then
        export AWS_REGION="$REGION"
        export AWS_DEFAULT_REGION="$REGION"
        export AWS_PROFILE="$AWS_PROFILE"
        export STACK_NAME="$STACK_NAME"
        bash scripts/setup-athena.sh
    else
        echo -e "${YELLOW}Athena setup script not found${NC}"
        echo "  Run manually: make setup-athena"
    fi
    echo ""
    
    # Step 4: Run Glue Crawler
    echo -e "${YELLOW}Step 4: Running Glue Crawler to discover partitions...${NC}"
    
    CRAWLER_NAME="${STACK_NAME}-crawler"
    aws glue start-crawler \
        --name "$CRAWLER_NAME" \
        --region "$REGION" \
        --profile "$AWS_PROFILE" 2>/dev/null || {
        echo -e "${YELLOW}Could not start crawler automatically${NC}"
        echo "  Run manually: aws glue start-crawler --name $CRAWLER_NAME"
    }
    
    # Wait for crawler to complete (with timeout)
    CRAWLER_TIMEOUT=60
    CRAWLER_ELAPSED=0
    while [ $CRAWLER_ELAPSED -lt $CRAWLER_TIMEOUT ]; do
        CRAWLER_STATE=$(aws glue get-crawler \
            --name "$CRAWLER_NAME" \
            --region "$REGION" \
            --profile "$AWS_PROFILE" \
            --query 'Crawler.State' \
            --output text 2>/dev/null)
        
        if [ "$CRAWLER_STATE" == "READY" ]; then
            echo -e "${GREEN}Glue Crawler completed${NC}"
            break
        fi
        
        sleep 5
        CRAWLER_ELAPSED=$((CRAWLER_ELAPSED + 5))
    done
    
    if [ $CRAWLER_ELAPSED -ge $CRAWLER_TIMEOUT ]; then
        echo -e "${YELLOW}Crawler still running (this is normal for large datasets)${NC}"
    fi
else
    echo -e "${YELLOW}Analytics is disabled - skipping S3 export and Athena setup${NC}"
fi

# Final status
echo ""
echo -e "${BLUE}================================================================${NC}"
echo -e "${GREEN}              Initialization Complete!${NC}"
echo -e "${BLUE}================================================================${NC}"
echo ""

echo -e "${GREEN}Your IAM Activity Tracker is now fully operational!${NC}"
echo ""

if [ "$EVENTS_PROCESSED" -gt 0 ]; then
    echo "Initial Status:"
    echo "   - ${GREEN}$EVENTS_PROCESSED${NC} events collected from CloudTrail"
    if [ "$ANALYTICS_ENABLED" == "true" ]; then
        echo "   - Data exported to S3: ${GREEN}s3://${ANALYTICS_BUCKET}/iam-events/${NC}"
        echo "   - Athena tables are ready for queries"
    fi
    echo "   - Real-time data available in DynamoDB"
    echo ""
fi

echo "What's Next:"
echo ""
if [ "$ANALYTICS_ENABLED" == "true" ]; then
    echo "1. Run analytics queries:"
    echo "   ${GREEN}make list-queries${NC}           # See available queries"
    echo "   ${GREEN}make run-query Q=failed_auth${NC} # Run specific query"
    echo ""
fi
echo "2. Monitor activity:"
echo "   ${GREEN}make logs${NC}                   # View recent logs"
echo "   ${GREEN}make status${NC}                 # Check system status"
echo ""
echo "3. Ongoing collection:"
echo "   - Tracker runs: Every hour (automatic)"
if [ "$ANALYTICS_ENABLED" == "true" ]; then
    echo "   - S3 export runs: Daily (automatic)"
fi
echo ""

# Clean up temp files
rm -f /tmp/tracker-response.json /tmp/exporter-response.json

echo -e "${GREEN}Happy monitoring!${NC}"