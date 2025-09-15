# IAM Activity Tracker

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.13-blue)](https://www.python.org/downloads/)
[![AWS SAM](https://img.shields.io/badge/AWS-SAM-orange)](https://aws.amazon.com/serverless/sam/)
[![Security](https://img.shields.io/badge/security-audit-green)](https://github.com/TarekCheikh-Org/my-iam-activity-trakcer)
[![Serverless](https://img.shields.io/badge/serverless-✓-brightgreen)](https://aws.amazon.com/serverless/)

A comprehensive serverless AWS solution for tracking and auditing IAM, STS, and AWS Console signin activities across all regions. Features real-time collection via free CloudTrail event history, advanced analytics with S3 + Athena, and automated security alerting. Built with AWS SAM, Lambda, DynamoDB, and optional Parquet analytics.

## Overview

IAM Activity Tracker provides comprehensive monitoring of authentication and authorization activities across your AWS account, helping you:

- Track who created, modified, or deleted IAM resources
- Monitor role assumptions and credential usage
- Detect suspicious authentication patterns and failed login attempts
- Monitor AWS Console login activity including root account usage
- Build compliance reports and audit trails
- Maintain event data beyond CloudTrail's 90-day limit
- Real-time security alerts for suspicious activities

## Features

### Event Collection
- **Multi-Region Support**: Automatically tracks IAM events (us-east-1), STS events (all regions), Console signin events (global), and SSO/Identity Center events
- **Complete Coverage**: Monitors IAM, STS, signin.amazonaws.com, and sso.amazonaws.com event sources
- **SSO Tracking**: Full support for AWS SSO/Identity Center administrative events (permission sets, account assignments, policy attachments)
- **Incremental Processing**: Only processes new events since last run with checkpoint management
- **Initial Collection**: First run collects up to 90 days of historical events from CloudTrail
- **Parallel Processing**: Uses multi-threading for fast regional queries (up to 32 concurrent threads)
- **Real-time Storage**: DynamoDB with GSI for immediate user and action queries
- **Smart Filtering**: Automatically filters out AWS service-linked role noise while preserving security-relevant events
- **Serverless**: No infrastructure to manage, fully event-driven architecture
- **Security Alerts**: Real-time SNS notifications for root usage, failed auth, privilege escalation, SSO admin actions, and more

### Analytics & Reporting
- **S3 Data Lake**: Optional daily export to S3 in optimized Parquet format
- **Athena Integration**: Query years of data with standard SQL
- **Pre-built Queries**: 15 ready-to-use security and compliance queries (including 6 SSO-specific queries)
- **Dual Output Format**: All queries support both table format (curated fields, no truncation) and JSON format (complete data)
- **Cost Optimization**: S3 lifecycle policies automatically archive old data
- **Query Tools**: Python CLI for running analytics programmatically with flexible output options

### Operational
- **Cost-Effective**: Operates within AWS free tier for most organizations
- **Customizable Schedule**: Configurable collection and export frequencies
- **Comprehensive Monitoring**: CloudWatch alarms for all functions
- **Easy Deployment**: Single-command SAM deployment

## Architecture

### Complete System Overview

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   EventBridge   │────▶│ Tracker Lambda   │────▶│    DynamoDB     │
│   (Hourly)      │     │(Multi-threaded)  │     │    (Events)     │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                               │                           │
                               ▼                           ▼
                        ┌──────────────────┐     ┌─────────────────┐
                        │ CloudTrail Event │     │Security Alerts  │
                        │   History API    │     │     (SNS)       │
                        │ (Free 90 days)   │     └─────────────────┘
                        └──────────────────┘               │
                                                           ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   EventBridge   │────▶│ Export Lambda    │     │   DynamoDB      │
│    (Daily)      │     │  (Parquet)       │     │   (Control)     │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                               │
                               ▼
                        ┌──────────────────┐     ┌─────────────────┐
                        │   S3 Bucket      │────▶│ Athena + Glue   │
                        │ (Data Lake)      │     │  (Analytics)    │
                        └──────────────────┘     └─────────────────┘
                               │                           │
                               ▼                           ▼
                        ┌──────────────────┐     ┌─────────────────┐
                        │ Lifecycle Rules  │     │  Query Tools    │
                        │(CostOptimization)│     │   (Python)      │
                        └──────────────────┘     └─────────────────┘
```

### Data Flow
1. **Collection**: Tracker Lambda queries CloudTrail every hour across all regions
2. **Storage**: Events stored in DynamoDB for real-time queries
3. **Export**: Export Lambda converts daily data to Parquet format in S3
4. **Analytics**: Glue crawlers discover partitions, Athena enables SQL queries
5. **Optimization**: S3 lifecycle rules archive old data to reduce costs

## Prerequisites

- AWS Account with appropriate permissions
- AWS CLI installed and configured
- SAM CLI installed ([Installation Guide](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html))
- Python 3.13 runtime support in your AWS region
- AWS SDK Pandas Layer for Python 3.13 (automatically configured in template)

### Required IAM Permissions

To deploy and operate the IAM Activity Tracker, your AWS user/role needs the following permissions:

- **CloudFormation**: Full access to create, update, and delete stacks
- **Lambda**: Create, update functions and execution roles
- **DynamoDB**: Create tables, indexes, and manage data
- **S3**: Create buckets and manage objects (if analytics enabled)
- **EventBridge**: Create and manage rules
- **CloudWatch**: Create log groups and alarms
- **IAM**: Create and manage service roles and policies
- **Glue**: Create databases, tables, and crawlers (if analytics enabled)

For deployment, you can use the AWS managed policy `PowerUserAccess` or create a custom policy with these specific permissions.

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/CloudinitFrance/iam-activity-tracker
cd iam-activity-tracker
```

### 2. Deploy the Solution

```bash
make deploy
```

![Make Help](assets/IAM-Activity-Tracker-Deploy.png)

The deployment will:
- Build the Lambda function
- Create an S3 bucket for deployment artifacts (if needed)
- Deploy the CloudFormation stack
- Set up all required resources

### 3. View Available Commands

```bash
make help
```

![Make Help](assets/IAM-Activity-Tracker-Help.png)

This shows all available commands including deployment, queries, and utilities.

## AWS Service Event Filtering

By default, the tracker filters out AWS service-linked role events to reduce noise and focus on security-relevant activities.

### What Gets Filtered?

Events are filtered based on CloudTrail's `userIdentity.type` field:
```json
{
  "userIdentity": {
    "type": "AWSService",
    "invokedBy": "elasticloadbalancing.amazonaws.com"
  }
}
```

### Why Filter AWS Service Events?

AWS services generate thousands of routine operational events that create noise in security monitoring:
- **Volume**: Can be 80-90% of total IAM/STS events
- **Operational**: Not indicative of user or application security activities
- **Cost**: Increases DynamoDB storage and processing costs
- **Alert fatigue**: Makes it harder to spot actual security incidents

## Configuration Options

### Environment Variables

#### Core Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `STACK_NAME` | iam-activity-tracker | CloudFormation stack name |
| `AWS_REGION` | us-east-1 | Deployment region |
| `LOG_LEVEL` | INFO | Logging verbosity (DEBUG/INFO/WARNING/ERROR) |

#### Collection Settings
| Variable | Default | Description |
|----------|---------|-------------|
| `SCHEDULE_EXPRESSION` | rate(1 hour) | How often to collect events |
| `MAX_WORKERS` | 16 | Max concurrent threads for region processing |
| `PROCESS_IAM_EVENTS` | true | Track IAM events (us-east-1) |
| `PROCESS_STS_EVENTS` | true | Track STS events (all regions) |
| `PROCESS_SIGNIN_EVENTS` | true | Track AWS Console signin events (us-east-1) |
| `PROCESS_SSO_EVENTS` | true | Track AWS SSO/Identity Center events |
| `SSO_REGION` | us-east-1 | Primary region for SSO events |
| `FILTER_AWS_SERVICE_EVENTS` | true | Filter out AWS service-linked role events |

#### Analytics Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_ANALYTICS` | true | Enable S3 export and Athena integration |
| `EXPORT_SCHEDULE_EXPRESSION` | rate(1 day) | How often to export to S3 |
| `EXPORT_DAYS_BACK` | 1 | Number of days to export per run |

#### Security Alerting Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_SECURITY_ALERTS` | true | Enable security alerts via SNS |
| `ALERTS_EMAIL_ADDRESS` | '' | Email address for security alerts (set during deployment or leave empty to skip) |
| `OFF_HOURS_START` | 22 | Start hour for off-hours alerts (24-hour format) |
| `OFF_HOURS_END` | 6 | End hour for off-hours alerts (24-hour format) |

### Schedule Options

#### Collection Frequency
- `rate(1 hour)` - Every hour (recommended for active environments)
- `rate(6 hours)` - Every 6 hours (cost-conscious option)
- `rate(12 hours)` - Twice daily (minimal active monitoring)
- `rate(1 day)` - Once daily (archive-focused)

#### Export Frequency
- `rate(6 hours)` - Every 6 hours (near real-time analytics)
- `rate(12 hours)` - Twice daily
- `rate(1 day)` - Daily (recommended for most use cases)
- `rate(7 days)` - Weekly (cost-optimized for large datasets)

## Cost Analysis

### Free Tier Coverage (DynamoDB Only)

For small organizations (<100 users, <50 service roles):
- **DynamoDB**: $0 (within 25GB free storage, 25 RCU/WCU)
- **Lambda**: $0 (within 1M invocations, 400,000 GB-seconds)
- **CloudTrail**: $0 (using free 90-day event history API)
- **CloudWatch**: $0 (within free tier limits)
- **Total**: $0/month

### With Analytics Enabled (S3 + Athena)

#### Small Organizations
- **Core components**: $0 (free tier)
- **S3 storage**: ~$0.50-2/month (depends on data retention)
- **Athena queries**: ~$0.10-1/month (depends on query frequency)
- **Total**: $0.60-3/month

#### Medium Organizations (500-1000 users)
- **DynamoDB**: $2-5/month (beyond free tier)
- **Lambda**: $0-2/month (increased execution time for exports)
- **S3 storage**: $2-8/month (more data, lifecycle optimization)
- **Athena**: $1-5/month (more frequent analytics)
- **Total**: $5-20/month

#### Large Organizations (1000+ users)
- **DynamoDB**: $10-25/month
- **Lambda**: $2-10/month
- **S3 storage**: $5-20/month (with lifecycle policies)
- **Athena**: $5-15/month
- **Glue**: $1-5/month (crawler executions)
- **Total**: $23-75/month

**Note**: Costs do not include SNS alerts (minimal, ~$0.10 per 1000 emails)

### Cost Optimization Features

1. **S3 Lifecycle Policies**: Automatically move data to cheaper storage classes
   - Standard (30 days) → Standard-IA (90 days) → Glacier (365 days) → Deep Archive
   - Can reduce storage costs by 80-95% for older data

2. **Parquet Format**: 70-90% smaller than JSON, reducing storage and query costs

3. **Partitioned Data**: Athena only scans relevant partitions, reducing query costs

4. **Conditional Deployment**: Disable analytics if only real-time monitoring is needed

## Querying the Data

### Real-time Queries (DynamoDB)

Perfect for recent data (last 30-90 days) and operational monitoring.

#### Using AWS Console
1. Navigate to DynamoDB in AWS Console
2. Select the events table (e.g., `iam-activity-tracker-events`)
3. Use Query or Scan with filters

#### Using AWS CLI
```bash
# Query events by user
aws dynamodb query \
  --table-name iam-activity-tracker-events \
  --index-name user_name-index \
  --key-condition-expression "user_name = :username" \
  --expression-attribute-values '{":username":{"S":"alice.johnson"}}'

# Query events by action
aws dynamodb query \
  --table-name iam-activity-tracker-events \
  --index-name event_name-index \
  --key-condition-expression "event_name = :eventname" \
  --expression-attribute-values '{":eventname":{"S":"CreateUser"}}'
```

### Analytics Queries (Athena)

Perfect for historical analysis, compliance reporting, and complex queries.

#### Quick Setup
```bash
# Create Athena tables (run after deployment and first export)
make setup-athena
```

![Setup Athena](assets/IAM-Activity-Tracker-Setup-Athena.png)

#### Pre-built Security Queries
```bash
# List all available queries
make list-queries

# Run specific security analysis (table format - default)
make run-query Q=failed_auth             # Failed authentication attempts
make run-query Q=root_usage              # Root account activity
make run-query Q=off_hours               # After-hours access
make run-query Q=active_users            # Most active users
make run-query Q=permission_changes      # IAM permission modifications
make run-query Q=role_assumptions        # Role usage patterns
make run-query Q=daily_summary           # Compliance reporting

# SSO/Identity Center queries
make run-query Q=sso_permission_sets     # SSO permission set changes
make run-query Q=sso_account_assignments # Account access grants
make run-query Q=sso_admin_policies      # Admin policy attachments
make run-query Q=sso_admin_users         # SSO administrators
make run-query Q=sso_activity_summary    # SSO usage overview

# JSON format for complete data (ALL queries support both formats!)
make run-query Q=failed_auth FORMAT=json             # Any IAM query
make run-query Q=root_usage FORMAT=json              
make run-query Q=sso_account_assignments FORMAT=json # Any SSO query
make run-query Q=sso_admin_policies FORMAT=json      
make run-query Q=active_users FORMAT=json            # Any analytics query
```

#### Output Formats

**ALL queries support two output formats:**

- **Table Format (default)**: Displays curated fields optimized to prevent truncation. Perfect for quick analysis and reporting.
- **JSON Format**: Returns complete data with all available fields. Ideal for detailed investigations or data export.

```bash
# Examples - Every query works with both formats
make run-query Q=user_lookup                  # Table format (default)
make run-query Q=user_lookup FORMAT=table     # Explicit table format
make run-query Q=user_lookup FORMAT=json      # JSON format with all fields

make run-query Q=sso_admin_policies          # Table format (default)
make run-query Q=sso_admin_policies FORMAT=json  # Complete data
```

#### Direct Athena Console Usage

For users who prefer AWS Athena console directly, all queries are available as ready-to-use SQL:

```bash
# View all queries in SQL format
cat queries/analytics_queries.sql

# Copy/paste any query directly into Athena console
# Queries use default table: iam_activity_tracker_database.iam_events
```

The `queries/analytics_queries.sql` file contains all 15 queries in standard SQL format, synchronized with the Python implementation. Perfect for:
- **Custom modifications**: Edit queries for specific requirements
- **Learning**: Understand the SQL behind each security analysis  
- **Integration**: Use with other tools beyond the CLI

![Available Queries](assets/IAM-Activity-Tracker-List-Queries.png)

**Example Query Output:**

![Failed Authentication Query](assets/IAM-Activity-Tracker-Failed-Auth.png)

#### Custom SQL Queries
```sql
-- Recent failed authentication attempts
SELECT 
    substr(event_time, 1, 10) as event_date,
    user_name,
    source_ip,
    event_name,
    error_code,
    COUNT(*) as failure_count
FROM iam_activity_tracker_database.iam_events
WHERE 
    substr(event_time, 1, 10) >= cast(current_date - INTERVAL '7' DAY as varchar)
    AND error_code IS NOT NULL AND error_code != ''
    AND event_name IN ('ConsoleLogin', 'AssumeRole', 'GetSessionToken')
GROUP BY 1, 2, 3, 4, 5
ORDER BY failure_count DESC;

-- Permission changes by user
SELECT 
    user_name,
    event_name,
    COUNT(*) as change_count,
    MIN(substr(event_time, 1, 10)) as first_change,
    MAX(substr(event_time, 1, 10)) as last_change
FROM iam_activity_tracker_database.iam_events
WHERE 
    substr(event_time, 1, 10) >= cast(current_date - INTERVAL '30' DAY as varchar)
    AND event_name IN (
        'AttachUserPolicy', 'DetachUserPolicy',
        'AttachGroupPolicy', 'DetachGroupPolicy',
        'AttachRolePolicy', 'DetachRolePolicy',
        'CreateUser', 'DeleteUser',
        'CreateRole', 'DeleteRole',
        'PutUserPolicy', 'DeleteUserPolicy'
    )
GROUP BY user_name, event_name
ORDER BY change_count DESC;

-- Role assumption patterns
SELECT 
    JSON_EXTRACT_SCALAR(request_parameters, '$.roleArn') as role_arn,
    user_name,
    COUNT(*) as assumption_count,
    COUNT(CASE WHEN error_code IS NOT NULL AND error_code != '' THEN 1 END) as failed_count
FROM iam_activity_tracker_database.iam_events
WHERE 
    substr(event_time, 1, 10) >= cast(current_date - INTERVAL '30' DAY as varchar)
    AND event_name = 'AssumeRole'
    AND JSON_EXTRACT_SCALAR(request_parameters, '$.roleArn') IS NOT NULL
GROUP BY 1, 2
ORDER BY assumption_count DESC
LIMIT 20;
```

### Example Outputs

The tool provides rich, formatted output for all queries with execution metrics:

![Query Output Example](assets/IAM-Activity-Tracker-Failed-Auth.png)

### Query Comparison

| Feature | DynamoDB | Athena |
|---------|----------|--------|
| **Best for** | Real-time, recent data | Historical analysis, complex queries |
| **Time range** | All data (no TTL by default) | All exported data |
| **Query language** | DynamoDB Query/Scan | Standard SQL |
| **Performance** | Milliseconds | Seconds to minutes |
| **Cost** | Free tier friendly | Pay per TB scanned |
| **Complexity** | Simple filters | Complex joins, aggregations |

## Monitoring

### CloudWatch Alarms

The solution includes CloudWatch alarms for:
- **Tracker Lambda**: Errors and high execution duration (>4 minutes)
- **Export Lambda**: Errors and high execution duration (>13 minutes)

### Viewing Logs

```bash
# View tracker Lambda logs with automatic formatting
make logs

# View specific log group
make logs | grep ERROR     # Filter for errors
make logs | grep CRITICAL  # Filter for critical alerts
```

### Health Checks

```bash
# Check stack status and outputs
make status

# Test a specific query
make run-query Q=failed_auth
```

## Maintenance

### Data Retention

By default, events are kept indefinitely. To enable automatic deletion:

1. Edit `template.yaml`
2. Add TTL configuration to IAMEventsTable
3. Redeploy the stack

### Updating the Solution

```bash
# Pull latest changes
git pull

# Update deployment
make update
```

## Troubleshooting

### Data Collection Issues

1. **"Access Denied" errors**
   - Ensure Lambda has CloudTrail read permissions in all regions
   - Verify CloudTrail is enabled (check AWS Console → CloudTrail)
   - Check IAM policy attached to tracker Lambda role

2. **High tracker Lambda duration**
   - Reduce MAX_WORKERS if hitting API rate limits
   - Consider increasing schedule interval to reduce frequency
   - Check CloudWatch metrics for throttling

3. **Missing events**
   - Verify PROCESS_IAM_EVENTS and PROCESS_STS_EVENTS are true
   - Check CloudWatch Logs for region-specific errors
   - Ensure all required AWS regions are accessible

### Analytics Issues

4. **No data in S3 bucket**
   - Check export Lambda logs for errors
   - Verify ENABLE_ANALYTICS is set to true
   - Ensure DynamoDB has data before export runs
   - Check S3 bucket permissions

5. **Athena queries return no results**
   - Run Glue crawler to discover new partitions:
     ```bash
     aws glue start-crawler --name iam-activity-tracker-crawler
     ```
   - Verify S3 data location in Athena table definition
   - Check partition projection configuration

6. **High Athena costs**
   - Use LIMIT in queries during testing
   - Add date filters to reduce data scanned
   - Check query execution plans
   - Consider partition pruning

7. **Export Lambda timeout**
   - Reduce EXPORT_DAYS_BACK to process fewer days per run
   - Increase Lambda memory (currently 2048MB)
   - Check if DynamoDB has throttling issues

### Performance Optimization

8. **Slow query performance**
   - Use appropriate indexes in DynamoDB
   - Add partition filters in Athena queries
   - Consider using columnar projection in Athena

9. **Cost optimization**
   - Enable S3 lifecycle policies (automatically configured)
   - Reduce query frequency if not needed real-time
   - Use Athena workgroups to set query limits

### Debug Mode

To enable verbose logging, update the CloudFormation stack parameter:
- Set `LogLevel` parameter to `DEBUG` during deployment

### Verification Commands

```bash
# Check DynamoDB table
aws dynamodb describe-table --table-name iam-activity-tracker-events

# Check S3 bucket (if analytics enabled)
aws s3 ls s3://iam-activity-tracker-analytics-ACCOUNT_ID/iam-events/ --recursive | head -5

# Test a query
make run-query Q=daily_summary
```

## Security Considerations

- Lambda function has read-only access to CloudTrail
- DynamoDB tables are encrypted at rest
- No credentials or sensitive data in logs
- Follows principle of least privilege

## Uninstall

To remove all resources:

```bash
make destroy
```

**Warning**: This will delete all collected event data!

**Important**: If analytics is enabled, manually empty the S3 buckets before running destroy:
```bash
aws s3 rm s3://iam-activity-tracker-analytics-ACCOUNT_ID/ --recursive
aws s3 rm s3://iam-activity-tracker-athena-results-ACCOUNT_ID/ --recursive
```

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review CloudWatch Logs
3. Open an issue in the repository

## Available Queries

### Pre-built Queries (15 total)

#### IAM & Security Queries
1. `user_lookup` - User activity patterns
2. `failed_auth` - Failed authentication attempts  
3. `root_usage` - Root account activity
4. `off_hours` - After-hours access (10 PM - 6 AM)
5. `active_users` - Most active users
6. `permission_changes` - IAM policy modifications
7. `role_assumptions` - Role usage patterns
8. `daily_summary` - Daily activity summaries
9. `hourly_activity` - Peak usage analysis

#### SSO/Identity Center Queries
10. `sso_permission_sets` - Track SSO permission set creation and updates
11. `sso_account_assignments` - Monitor who is getting access to which AWS accounts
12. `sso_admin_policies` - Track dangerous administrative policy attachments
13. `sso_applications` - Monitor third-party application integrations
14. `sso_admin_users` - Identify users making SSO configuration changes
15. `sso_activity_summary` - SSO usage patterns and error rates

### Security Alerts (8 functions)
1. Root account activity (login/failed)
2. IAM user creation
3. Admin policy attachments
4. Dangerous inline policies
5. Access key creation
6. Role trust policy issues
7. Access key updates
8. MFA device changes

## File Structure

```
iam-activity-tracker/
├── assets/                          # Screenshots and documentation
│   ├── Failed_Auth.png
│   └── List_Queries.png
├── functions/                       # Lambda function code
│   ├── tracker/                     # Real-time event collection
│   │   ├── handler.py               # Main tracker Lambda
│   │   ├── cloudtrail_processor.py
│   │   ├── dynamodb_operations.py
│   │   ├── security_alerts.py       # SNS alerting logic
│   │   └── requirements.txt
│   └── exporter/                    # S3 analytics export
│       ├── export_handler.py        # Export Lambda
│       ├── parquet_processor.py
│       ├── s3_operations.py
│       ├── dynamodb_operations.py
│       └── requirements.txt
├── queries/                         # Analytics tools
│   ├── athena_utilities.py          # Athena integration
│   ├── query_runner.py              # CLI query tool
│   ├── analytics_queries.sql        # Pre-built SQL queries
│   ├── setup.sh                     # Python environment setup
│   └── requirements.txt
├── scripts/                         # Operational scripts
│   ├── deploy.sh                    # Deployment script
│   ├── destroy.sh                   # Cleanup script
│   ├── logs.sh                      # View Lambda logs
│   ├── run-query.sh                 # Query execution wrapper
│   ├── setup-athena.sh              # Athena table setup
│   ├── status.sh                    # Stack status check
│   ├── test-alerts.sh               # Test alert system
│   └── validate.sh                  # Template validation
├── template.yaml                    # SAM deployment template
├── Makefile                         # Build automation
├── Architecture.md                  # Detailed system design
└── README.md                        # This file
```

---

Built for the AWS security community
