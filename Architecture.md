# AWS IAM Activity Tracker Architecture

## Overview
A comprehensive serverless solution for tracking IAM, STS, and Console signin activities using AWS-native services, designed to operate within AWS free tier limits for most use cases. Features real-time security alerting and advanced analytics capabilities.

## Important: Event Source Locations

**Critical Understanding**:
- **IAM events** (iam.amazonaws.com) are recorded ONLY in **us-east-1** regardless of where the API call originates
- **STS events** (sts.amazonaws.com) are recorded in the **region where the assume role call was made**
- **Signin events** (signin.amazonaws.com) are recorded ONLY in **us-east-1** for global console authentication
- All three event types are essential for complete activity tracking

## Architecture Components

### 1. **DynamoDB Tables (3 total)**

#### a) **IAM Events Table** (Primary Storage)
- **Table Name**: `{stack-name}-events`
- **Purpose**: Store IAM, STS, signin, and SSO/Identity Center events efficiently with fast query capabilities
- **Schema Design**:
  - **Partition Key**: `event_date` (format: YYYY-MM-DD)
  - **Sort Key**: `event_id` (CloudTrail Event ID)
  - **Attributes**: 
    - `event_time` (ISO timestamp)
    - `event_name` (CloudTrail action)
    - `event_source` (iam/sts/signin.amazonaws.com/sso.amazonaws.com)
    - `event_type` (parsed: iam/sts/signin/sso)
    - `user_name` (extracted user/role name)
    - `aws_region` (important for STS and SSO events)
    - `source_ip`
    - `user_agent`
    - `request_parameters` (JSON)
    - `response_elements` (JSON)
    - `error_code` (if failed)
    - `error_message` (if failed)
- **Global Secondary Indexes**: 
  - GSI on `user_name` for user-specific queries
  - GSI on `event_name` for action-specific queries
- **TTL**: Optional - set on items older than configured retention period

#### b) **Processing Control Table**
- **Table Name**: `{stack-name}-control`
- **Purpose**: Track processing state and checkpoints per region/source
- **Schema Design**:
  - **Partition Key**: `region` (e.g., "us-east-1-iam", "eu-west-1-sts", "us-east-1-signin")
  - **Attributes**:
    - `last_processed_timestamp` (ISO timestamp of last event processed)
    - `last_execution_time` (when Lambda last ran for this source)
    - `events_processed_count` (running total)
    - `last_error` (if any)
    - `processing_status` (active/paused/error)
- **Separate checkpoints for each region/source combination**

#### c) **Alerts Table** (Alert Deduplication)
- **Table Name**: `{stack-name}-alerts`
- **Purpose**: Prevent duplicate alert notifications
- **Schema Design**:
  - **Partition Key**: `event_id` (CloudTrail Event ID)
  - **Sort Key**: `alert_type` (CRITICAL/HIGH/WARNING)
  - **Attributes**:
    - `alert_title` (Alert description)
    - `message_id` (SNS message ID)
    - `sent_timestamp` (when alert was sent)
    - `ttl` (30-day expiration)
- **TTL Enabled**: 30-day retention to keep alerts history but not forever

### 2. **Lambda Functions**

#### a) **Tracker Lambda** (`functions/tracker/`)
- **Handler**: `handler.lambda_handler`
- **Purpose**: Query CloudTrail across regions and sources for events
- **Runtime**: Python 3.13
- **Memory**: 1024MB (increased for multi-threading performance)
- **Timeout**: 5 minutes (300 seconds)
- **Environment Variables**:
  - `PROCESS_IAM_EVENTS=true`
  - `PROCESS_STS_EVENTS=true`
  - `PROCESS_SIGNIN_EVENTS=true`
  - `FILTER_AWS_SERVICE_EVENTS=true`
  - `FILTERED_ROLES=''` (comma-separated role patterns to filter)
  - `ALERTS_ENABLED=true`
  - `MAX_WORKERS=16`

**Modules**:
- **`handler.py`**: Main Lambda entry point with multi-threading coordination
- **`cloudtrail_processor.py`**: CloudTrail API queries and event parsing
- **`dynamodb_operations.py`**: DynamoDB batch writes and checkpoint management
- **`security_alerts.py`**: Real-time security alert analysis and SNS notifications

**Key Functions**:
- Query us-east-1 CloudTrail for IAM events (iam.amazonaws.com)
- Query us-east-1 CloudTrail for Signin events (signin.amazonaws.com)
- Query all active regions for STS events using multi-threading
- Process up to 32 regions/sources in parallel
- Smart user name extraction (role names from AssumeRole, root from ConsoleLogin)
- **Role filtering**: Filter out noisy CSPM/security tool roles using configurable patterns
- Real-time security alert checking
- Transform and batch store in DynamoDB

**Performance Optimizations**:
- ThreadPoolExecutor with configurable max_workers
- Batch write to DynamoDB (25 items per batch)
- Connection pooling for AWS SDK clients
- Separate processing threads for each region/source

#### b) **Exporter Lambda** (`functions/exporter/`)
- **Handler**: `export_handler.lambda_handler`
- **Purpose**: Export DynamoDB data to S3 in Parquet format
- **Runtime**: Python 3.13
- **Memory**: 2048MB (for Pandas/PyArrow processing)
- **Timeout**: 15 minutes (900 seconds)
- **Layer**: AWSSDKPandas-Python313

**Modules**:
- **`export_handler.py`**: Main export logic and date range management
- **`parquet_processor.py`**: Pandas/PyArrow Parquet conversion
- **`s3_operations.py`**: S3 bucket operations and path generation
- **`dynamodb_operations.py`**: DynamoDB scan operations for export

**Features**:
- Daily synchronization of missing dates
- Partitioned Parquet output by year/month/day/region
- Optimized compression and columnar storage
- Incremental export (only new/missing data)

### 3. **Security Alerting System**

#### a) **SNS Topic**
- **Purpose**: Send real-time security notifications
- **Features**:
  - Email subscriptions (configurable)
  - Message attributes for filtering
  - KMS encryption for sensitive alerts

#### b) **Alert Functions (14 total)**
**From `security_alerts.py`**:

1. **`check_root_activity`**: Root account login/failed login (CRITICAL)
2. **`check_user_creation`**: IAM user creation (HIGH)
3. **`check_admin_policy_attachment`**: Admin policy attachments (CRITICAL)
   - Detects: AdministratorAccess, IAMFullAccess, PowerUserAccess, AWSSSOMasterAccountAdministrator, AWSIdentityCenterFullAccess, AWSSSOMemberAccountAdministrator
4. **`check_dangerous_inline_policy`**: Policies with *, iam:*, sts:* (CRITICAL)
5. **`check_access_key_creation`**: New access key generation (CRITICAL)
6. **`check_role_trust_policy`**: External account/wildcard principals (CRITICAL)
7. **`check_access_key_update`**: Access key status changes (HIGH)
8. **`check_mfa_deletion`**: MFA device deletion/deactivation (CRITICAL)
9. **`check_sso_permission_set_creation`**: SSO permission set creation (CRITICAL)
10. **`check_sso_permission_set_update`**: SSO permission set updates (CRITICAL)
11. **`check_sso_admin_policy_attachment`**: Admin policy attached to SSO permission set (CRITICAL)
12. **`check_sso_account_assignment`**: SSO account assignment created (CRITICAL)
13. **`check_sso_app_creation`**: SSO managed application instance creation (HIGH)
14. **`check_sso_app_deletion`**: SSO managed application instance deletion (HIGH)

**Alert Processing**:
- Real-time analysis of each stored event
- Deduplication via alerts table (30-day TTL)
- Non-blocking processing (failures don't stop event collection)
- SNS notifications with detailed context

### 4. **EventBridge Schedulers**
- **Tracker Schedule**: Configurable (hourly/6h/12h/daily)
- **Exporter Schedule**: Configurable (6h/12h/daily/weekly)
- **Cost**: Free for rule creation and invocations

### 5. **S3 + Athena Analytics** (Optional)

#### a) **Analytics Bucket**
- **Purpose**: Long-term storage and complex analytics
- **Structure**:
  ```
  s3://{stack-name}-analytics-{account-id}/
    iam-events/
      year=2024/
        month=1/          # No leading zeros (for Athena partition projection)
          day=15/         # No leading zeros (for Athena partition projection)
            region=us-east-1/     # Only if PARTITION_BY_REGION=true
              events_20240115_143052.parquet  # Timestamp for uniqueness
  ```
- **Format**: Parquet with snappy compression
- **Partitioning**: By year/month/day/region for query optimization
- **Lifecycle Policy**: 
  - Standard → Infrequent Access after 30 days
  - Infrequent Access → Glacier after 90 days
  - Deep Archive after 365 days

#### b) **Athena Integration**
- **Glue Database**: Automatically managed schema
- **Glue Crawler**: Daily partition discovery
- **Athena WorkGroup**: Dedicated workspace with result location
- **Pre-built Queries**: 9 security and compliance queries

#### c) **Query Utilities**
- **Python CLI**: `query_runner.py` for programmatic access
- **Rich Terminal Output**: Color-coded tables with formatting
- **Export Capabilities**: JSON output for integration
- **Cost Tracking**: Query execution metrics and cost estimation

## Data Processing Flow

### 1. **Event Collection**
```
EventBridge Timer → Tracker Lambda → [Parallel Processing]
                                   ├─ us-east-1 (IAM events)
                                   ├─ us-east-1 (Signin events)
                                   ├─ us-east-1/configured (SSO events)
                                   ├─ us-west-2 (STS events)
                                   ├─ eu-west-1 (STS events)
                                   └─ ... (all active regions)
```

### 2. **Data Transformation**
- **User Name Extraction**:
  - AssumeRole events: Extract role name from `requestParameters.roleArn`
  - ConsoleLogin events: Extract "root" or IAM username from `userIdentity`
  - Other events: Use existing logic for session context and ARNs
- **Event Type Classification**: iam/sts/signin based on event source
- **Error Handling**: Capture both `errorCode` and `errorMessage` fields
- **JSON Serialization**: Store complex parameters as JSON strings

### 3. **Storage Strategy**
```
Processed Events → DynamoDB (Real-time) → Security Alerts → SNS
                             ↓
                         Daily Export → S3 (Parquet) → Athena (Analytics)
```

### 4. **Incremental Processing**

#### Initial Load
1. Lambda queries last 90 days of CloudTrail events per source:
   - **us-east-1**: IAM events (iam.amazonaws.com)
   - **us-east-1**: Signin events (signin.amazonaws.com)
   - **All regions**: STS events (sts.amazonaws.com)
2. Stores all events in DynamoDB with source/region information
3. Records latest EventTime as checkpoint per region/source

#### Incremental Updates
1. Lambda reads last checkpoint from DynamoDB control table (per region/source)
2. For each region/source combination:
   - Queries CloudTrail: `StartTime = checkpoint + 1 second, EndTime = now() - 5 minutes`
   - 5-minute buffer prevents missing in-flight events
3. Processes and stores new events
4. Updates checkpoint for each region/source separately
5. Triggers security alert analysis for each event

### 5. **Multi-Threading Architecture**
```python
with ThreadPoolExecutor(max_workers=32) as executor:
    futures = []
    
    # IAM events (us-east-1 only)
    if PROCESS_IAM_EVENTS:
        futures.append(executor.submit(process_region_events, 
                                     'us-east-1', 'iam.amazonaws.com'))
    
    # Signin events (us-east-1 only)  
    if PROCESS_SIGNIN_EVENTS:
        futures.append(executor.submit(process_region_events,
                                     'us-east-1', 'signin.amazonaws.com'))
    
    # STS events (all regions)
    if PROCESS_STS_EVENTS:
        for region in active_regions:
            futures.append(executor.submit(process_region_events,
                                         region, 'sts.amazonaws.com'))
    
    # Gather results with timeout
    for future in as_completed(futures, timeout=240):
        events_processed += future.result()
```

## Query System

### Pre-built Queries (15 total)
**From `query_runner.py` QUERY_DEFINITIONS**:

1. **`user_lookup`**: User activity patterns and identification
2. **`failed_auth`**: Failed authentication attempts and brute force detection
3. **`root_usage`**: Root account activity detection
4. **`off_hours`**: After-hours access outside 6 AM - 10 PM
5. **`active_users`**: Most active users with usage patterns and error rates
6. **`permission_changes`**: IAM policy modifications tracking
7. **`role_assumptions`**: Role usage patterns and frequency analysis
8. **`daily_summary`**: Daily activity summaries for compliance reporting
9. **`hourly_activity`**: Peak usage analysis for capacity planning
10. **`sso_permission_sets`**: SSO permission set management tracking
11. **`sso_account_assignments`**: SSO account assignment tracking
12. **`sso_admin_policies`**: SSO admin policy attachment detection
13. **`sso_applications`**: SSO application management tracking
14. **`sso_admin_users`**: SSO administrative users identification
15. **`sso_activity_summary`**: SSO usage patterns by event type

### Query Infrastructure
- **`athena_utilities.py`**: Core Athena operations (execute_athena_query, create_iam_events_table, get_table_statistics, validate_s3_location)
- **`query_runner.py`**: Main CLI tool with QUERY_DEFINITIONS dictionary containing all 15 pre-built queries, Rich terminal formatting support
- **`analytics_queries.sql`**: Reference SQL queries (if present)

## Operational Scripts

### Core Scripts (`scripts/` folder)
- **`deploy.sh`**: SAM deployment with S3 bucket creation, automatic AWS CLI/SAM CLI installation in venv
- **`destroy.sh`**: CloudFormation stack deletion with confirmation prompt
- **`status.sh`**: Formatted stack status display with colored output
- **`validate.sh`**: Template validation
- **`logs.sh`**: Lambda log viewing
- **`run-query.sh`**: Query execution wrapper
- **`setup-athena.sh`**: Athena table initialization
- **`test-alerts.sh`**: SNS alert testing

### Query Tools (`queries/` folder)
- **`query_runner.py`**: Main CLI tool with 15 pre-built analytics queries
- **`athena_utilities.py`**: Athena query execution and table management
- **`requirements.txt`**: Python dependencies (boto3, rich for terminal formatting)

## Security Alert Message Format
```
Subject: [CRITICAL] IAM Alert: Root Account Login

IAM Activity Alert: Root Account Login
Severity: CRITICAL
Time: 2025-08-10T18:26:07+00:00
Region: us-east-1

Root account logged in from IP: 90.7.221.136

Event Details:
- Event Name: ConsoleLogin
- User: root
- Source IP: 90.7.221.136  
- Event ID: b5636e39-f66f-4ce1-b9f1-2368c72b7fc6

Action Required: Review this activity immediately in CloudTrail.
```

## Cost Analysis

### Within Free Tier (Most Cases)
- **DynamoDB**: Free (25GB storage, 25 RCU/WCU)
- **Lambda**: Free (1M invocations, 400,000 GB-seconds)
- **SNS**: Free (1,000 notifications)
- **EventBridge**: Free
- **CloudTrail**: Free (90-day event history)
- **S3**: Free (5GB standard storage)
- **Total**: $0/month for most organizations

### Beyond Free Tier (Active Organizations)
- **DynamoDB**: ~$0.25/GB/month + $0.00013/RCU + $0.00065/WCU
- **Lambda**: $0.20 per 1M requests + $0.0000166667/GB-second
- **SNS**: $0.50 per 1M notifications (beyond free tier)
- **S3**: $0.023/GB/month (standard) with lifecycle transitions
- **Athena**: $5 per TB scanned (only when running queries)
- **Estimated**: $5-20/month for very active organizations

### Cost Optimization Features
- Automatic DynamoDB on-demand pricing (pay per request)
- S3 lifecycle policies for automatic archiving
- Configurable processing schedules
- Query result caching in Athena
- Parquet compression reduces storage costs by 75%

## Security Considerations

### IAM Permissions
1. **Tracker Lambda Execution Role**:
   - `cloudtrail:LookupEvents` in all regions
   - `dynamodb:PutItem`, `GetItem`, `UpdateItem`, `Query`, `BatchWriteItem` on events table
   - `dynamodb:PutItem`, `GetItem`, `UpdateItem` on control table
   - `dynamodb:PutItem`, `GetItem` on alerts table
   - `sns:Publish` on alerts topic (if enabled)
   - `ec2:DescribeRegions` for region enumeration

2. **Exporter Lambda Execution Role**:
   - `dynamodb:Scan`, `Query` on events table
   - `s3:PutObject`, `GetObject`, `ListBucket` on analytics bucket

3. **Query User Permissions**:
   - `athena:StartQueryExecution`, `GetQueryResults`
   - `s3:GetObject` on analytics bucket
   - `glue:GetDatabase`, `GetTable`, `GetPartitions`

### Data Protection
- **Encryption at Rest**: DynamoDB and S3 use AWS managed keys
- **Encryption in Transit**: TLS 1.2+ for all API calls
- **Access Control**: Fine-grained IAM policies
- **Network Security**: Lambda functions run in AWS-managed VPCs
- **Data Retention**: Configurable TTL and lifecycle policies

## Key Events Tracked

### IAM Events (iam.amazonaws.com)
- `CreateUser`, `DeleteUser`, `UpdateUser`
- `AttachUserPolicy`, `DetachUserPolicy`
- `CreateAccessKey`, `DeleteAccessKey`, `UpdateAccessKey`
- `CreateRole`, `DeleteRole`, `UpdateRole`
- `PutRolePolicy`, `DeleteRolePolicy`
- `AttachRolePolicy`, `DetachRolePolicy`
- `CreateLoginProfile`, `UpdateLoginProfile`

### STS Events (sts.amazonaws.com)
- `AssumeRole` - Most critical for tracking role usage
- `AssumeRoleWithWebIdentity` - Federation tracking
- `AssumeRoleWithSAML` - Enterprise SSO tracking
- `GetSessionToken` - Temporary credential usage
- `GetFederationToken` - Federation token requests

### Signin Events (signin.amazonaws.com)
- `ConsoleLogin` - AWS Console authentication (success/failure)
- `SwitchRole` - Role switching in console
- `ExitRole` - Role exit in console

### SSO/Identity Center Events (sso.amazonaws.com)
- `CreatePermissionSet`, `UpdatePermissionSet` - Permission set management
- `AttachManagedPolicyToPermissionSet` - Policy attachments (critical for admin access)
- `CreateAccountAssignment`, `DeleteAccountAssignment` - Account access grants
- `CreateManagedApplicationInstance` - Third-party app integrations
- `Federate` - SSO authentication events

## File Structure Implementation
```
iam-activity-tracker/
├── functions/                       # Lambda function code
│   ├── tracker/                     # Real-time event collection
│   │   ├── handler.py               # Main tracker Lambda entry point
│   │   ├── cloudtrail_processor.py  # CloudTrail API and event parsing
│   │   ├── dynamodb_operations.py   # DynamoDB operations and checkpoints
│   │   ├── security_alerts.py       # 8 alert functions and SNS notifications
│   │   └── requirements.txt
│   └── exporter/                    # S3 analytics export
│       ├── export_handler.py        # Export Lambda entry point
│       ├── parquet_processor.py     # Pandas/PyArrow Parquet conversion
│       ├── s3_operations.py         # S3 bucket operations and paths
│       ├── dynamodb_operations.py   # DynamoDB scan for export
│       └── requirements.txt
├── queries/                         # Analytics tools
│   ├── athena_utilities.py          # Athena query execution
│   ├── query_runner.py              # CLI with 9 pre-built queries
│   ├── analytics_queries.sql        # Raw SQL for reference
│   ├── setup.sh                     # Python environment and venv setup
│   └── requirements.txt
├── scripts/                         # Operational scripts
│   ├── deploy.sh                    # SAM deployment
│   ├── destroy.sh                   # Stack cleanup
│   ├── status.sh                    # Stack status display
│   ├── validate.sh                  # Template validation
│   ├── logs.sh                      # Lambda log viewing
│   ├── run-query.sh                 # Query execution wrapper
│   ├── setup-athena.sh              # Athena table setup
│   └── test-alerts.sh               # Alert testing
├── template.yaml                    # SAM deployment template
└── README.md                        # User documentation
```

## Monitoring and Maintenance

### CloudWatch Alarms
- **Function Errors**: Alert on any Lambda execution failures
- **Function Duration**: Alert on timeouts or high latency
- **DynamoDB Throttling**: Alert on capacity exceeded
- **S3 Export Failures**: Alert on export Lambda failures

### Log Groups
- `/aws/lambda/{stack-name}-tracker`: Event collection logs
- `/aws/lambda/{stack-name}-exporter`: S3 export logs
- CloudTrail event details in structured JSON format

This architecture provides complete visibility into IAM activities while maintaining cost-effectiveness and operational simplicity through serverless design patterns.