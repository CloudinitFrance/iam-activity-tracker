#!/bin/bash

# IAM Activity Tracker Logs Script
# Shows recent CloudWatch logs for the tracker function

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
FOLLOW="${1:-false}"

if [ -z "$AWS_REGION" ] || [ -z "$AWS_PROFILE" ]; then
    echo -e "${RED}Error: AWS_REGION and AWS_PROFILE environment variables must be set${NC}"
    exit 1
fi

LOG_GROUP="/aws/lambda/$STACK_NAME-tracker"

# Get timestamp for 1 hour ago (cross-platform)
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    ONE_HOUR_AGO="$(date -v-1H +%s)000"
else
    # Linux
    ONE_HOUR_AGO="$(date -d '1 hour ago' +%s)000"
fi

if [ "$FOLLOW" = "follow" ]; then
    # Try AWS CLI v2 tail command
    echo -e "${YELLOW}Following logs for $STACK_NAME-tracker... (Press Ctrl+C to stop)${NC}"
    aws logs tail "$LOG_GROUP" \
        --region "$AWS_REGION" \
        --profile "$AWS_PROFILE" \
        --follow 2>/dev/null || \
        (echo -e "${RED}Error: 'aws logs tail' requires AWS CLI v2. Showing recent log streams instead...${NC}" && \
         echo "" && \
         echo -e "${YELLOW}Available log streams:${NC}" && \
         aws logs describe-log-streams \
            --log-group-name "$LOG_GROUP" \
            --region "$AWS_REGION" \
            --profile "$AWS_PROFILE" \
            --order-by LastEventTime \
            --descending \
            --max-items 5 \
            --query 'logStreams[*].[logStreamName,lastEventTime,lastIngestionTime]' \
            --output table && \
         echo "" && \
         echo -e "${YELLOW}Recent events from latest stream:${NC}" && \
         LATEST_STREAM=$(aws logs describe-log-streams \
            --log-group-name "$LOG_GROUP" \
            --region "$AWS_REGION" \
            --profile "$AWS_PROFILE" \
            --order-by LastEventTime \
            --descending \
            --max-items 1 \
            --query 'logStreams[0].logStreamName' \
            --output text) && \
         aws logs get-log-events \
            --log-group-name "$LOG_GROUP" \
            --log-stream-name "$LATEST_STREAM" \
            --region "$AWS_REGION" \
            --profile "$AWS_PROFILE" \
            --query 'events[*].[timestamp,message]' \
            --output table)
else
    # Show recent logs using log streams (AWS CLI v1 compatible)
    echo -e "${YELLOW}Recent logs for $STACK_NAME-tracker:${NC}"
    echo ""
    
    # Get the latest log stream
    LATEST_STREAM=$(aws logs describe-log-streams \
        --log-group-name "$LOG_GROUP" \
        --region "$AWS_REGION" \
        --profile "$AWS_PROFILE" \
        --order-by LastEventTime \
        --descending \
        --max-items 1 \
        --query 'logStreams[0].logStreamName' \
        --output text 2>/dev/null | head -n1 | tr -d '\n')
    
    if [ -n "$LATEST_STREAM" ] && [ "$LATEST_STREAM" != "None" ]; then
        # Get recent events from the latest stream - clean format
        aws logs get-log-events \
            --log-group-name "$LOG_GROUP" \
            --log-stream-name "$LATEST_STREAM" \
            --region "$AWS_REGION" \
            --profile "$AWS_PROFILE" \
            --query 'events[-20:].message' \
            --output text | while IFS= read -r line; do
            if [[ $line =~ ^\[INFO\] ]]; then
                echo -e "${GREEN}$line${NC}"
            elif [[ $line =~ ^\[WARN\] ]]; then
                echo -e "${YELLOW}$line${NC}"
            elif [[ $line =~ ^\[ERROR\] ]]; then
                echo -e "${RED}$line${NC}"
            elif [[ $line =~ ^(START|END|REPORT) ]]; then
                echo -e "${YELLOW}$line${NC}"
            else
                echo "$line"
            fi
        done
    else
        echo -e "${RED}No log streams found or function hasn't been executed recently${NC}"
        echo ""
        echo -e "${YELLOW}Available log streams:${NC}"
        aws logs describe-log-streams \
            --log-group-name "$LOG_GROUP" \
            --region "$AWS_REGION" \
            --profile "$AWS_PROFILE" \
            --order-by LastEventTime \
            --descending \
            --max-items 5 \
            --query 'logStreams[*].[logStreamName,lastEventTime]' \
            --output table 2>/dev/null || echo "No log streams found"
    fi
fi