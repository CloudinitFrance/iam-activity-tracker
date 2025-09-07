#!/bin/bash

# IAM Activity Tracker Validation Script
# Validates the SAM template with formatted output

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
echo -e "${GREEN}                    IAM Activity Tracker - Template Validation${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${YELLOW}Validating template...${NC}"
echo ""

# Run basic validation
if sam validate 2>&1 | grep -q "is a valid SAM Template"; then
    echo -e "${GREEN}✓ Basic Validation:${NC} Passed"
    echo "  Template syntax is valid"
    echo "  Resource definitions are correct"
    echo "  Parameter declarations are valid"
else
    echo -e "${RED}✗ Basic Validation:${NC} Failed"
    sam validate
    exit 1
fi

echo ""

# Run enhanced validation with lint
echo -e "${YELLOW}Running enhanced validation with linting...${NC}"
echo ""

LINT_OUTPUT=$(sam validate --lint 2>&1 || true)

if echo "$LINT_OUTPUT" | grep -q "Error"; then
    echo -e "${RED}✗ Lint Validation:${NC} Found issues"
    echo "$LINT_OUTPUT" | grep -E "(Error|Warning)" | sed 's/^/  /'
else
    echo -e "${GREEN}✓ Lint Validation:${NC} Passed"
    echo "  No linting errors found"
    echo "  Best practices validated"
fi

echo ""

# Check template file details
TEMPLATE_SIZE=$(ls -lh template.yaml | awk '{print $5}')
RESOURCE_COUNT=$(grep -c "Type: AWS::" template.yaml || echo "0")
PARAMETER_COUNT=$(grep -A1000 "^Parameters:" template.yaml | grep -c "^  [A-Za-z]" || echo "0")
OUTPUT_COUNT=$(grep -A1000 "^Outputs:" template.yaml | grep -c "^  [A-Za-z]" || echo "0")

echo -e "${YELLOW}Template Summary:${NC}"
echo "  File:         template.yaml"
echo "  Size:         $TEMPLATE_SIZE"
echo "  Resources:    $RESOURCE_COUNT"
echo "  Parameters:   $PARAMETER_COUNT"
echo "  Outputs:      $OUTPUT_COUNT"
echo ""

# Show validation details
echo -e "${YELLOW}Validation Details:${NC}"
echo "  Region:       $AWS_REGION"
echo "  Profile:      $AWS_PROFILE"
echo "  Stack Name:   $STACK_NAME"
echo ""

echo -e "${GREEN}✓ Template validation complete!${NC}"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "  To deploy this template, run:"
echo -e "  ${GREEN}make deploy${NC}"
echo ""