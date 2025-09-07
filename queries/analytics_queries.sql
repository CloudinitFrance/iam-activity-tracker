-- IAM Activity Analytics Queries
-- Pre-built queries for common security and compliance use cases
-- 
-- Default configuration: iam_activity_tracker_database.iam_events
-- If your database/table names differ, find/replace throughout this file
--
-- RECOMMENDED: Use 'make run-query Q=<query_name>' for automated execution with proper formatting
-- These queries match the Python query_runner.py implementation exactly

-- =============================================================================
-- 1. USER AND ACCESS QUERIES
-- =============================================================================

-- Query: user_lookup - User Activity Summary
-- Purpose: Identify and analyze user activity patterns
SELECT 
    COALESCE(
        REGEXP_EXTRACT(user_name, ':(.+)$', 1),
        JSON_EXTRACT_SCALAR(request_parameters, '$.roleSessionName'),
        user_name
    ) as user_identity,
    substr(MIN(event_time), 1, 16) as first_activity,
    substr(MAX(event_time), 1, 16) as last_activity,
    COUNT(*) as total_events,
    COUNT(DISTINCT event_name) as unique_actions,
    COUNT(DISTINCT substr(event_time, 1, 10)) as days_active
FROM iam_activity_tracker_database.iam_events
WHERE 
    substr(event_time, 1, 10) >= cast(current_date - INTERVAL '30' DAY as varchar)
    AND user_name != 'unknown'
GROUP BY 
    COALESCE(
        REGEXP_EXTRACT(user_name, ':(.+)$', 1),
        JSON_EXTRACT_SCALAR(request_parameters, '$.roleSessionName'),
        user_name
    )
ORDER BY total_events DESC
LIMIT 25;

-- Query: failed_auth - Failed Authentication Attempts
-- Purpose: Identify potential brute force attacks or credential issues
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
    AND error_code IS NOT NULL 
    AND error_code != ''
    AND event_name IN ('AssumeRole', 'GetSessionToken', 'ConsoleLogin')
GROUP BY 
    substr(event_time, 1, 10),
    user_name,
    source_ip,
    event_name,
    error_code
ORDER BY failure_count DESC, event_date DESC
LIMIT 100;

-- Query: root_usage - Root Account Activity
-- Purpose: Alert on any root account activity (security best practice violation)
SELECT 
    event_time,
    event_name,
    source_ip,
    user_agent,
    aws_region,
    error_code,
    request_parameters,
    response_elements
FROM iam_activity_tracker_database.iam_events
WHERE 
    substr(event_time, 1, 10) >= cast(current_date - INTERVAL '30' DAY as varchar)
    AND (user_name = 'root' OR user_name LIKE '%root%')
ORDER BY event_time DESC
LIMIT 100;

-- Query: off_hours - Off-Hours Activity
-- Purpose: Detect after-hours access that might indicate compromise
SELECT 
    COALESCE(
        REGEXP_EXTRACT(user_name, ':(.+)$', 1),
        JSON_EXTRACT_SCALAR(request_parameters, '$.roleSessionName'),
        user_name
    ) as user_identity,
    event_name,
    COUNT(*) as event_count,
    MIN(event_time) as first_occurrence,
    MAX(event_time) as last_occurrence
FROM iam_activity_tracker_database.iam_events
WHERE 
    substr(event_time, 1, 10) >= cast(current_date - INTERVAL '90' DAY as varchar)
    AND (cast(substr(event_time, 12, 2) as integer) < 6 OR cast(substr(event_time, 12, 2) as integer) > 22)
    AND user_name != 'unknown'
    AND source_ip NOT LIKE '%.amazonaws.com'
GROUP BY 
    COALESCE(
        REGEXP_EXTRACT(user_name, ':(.+)$', 1),
        JSON_EXTRACT_SCALAR(request_parameters, '$.roleSessionName'),
        user_name
    ),
    event_name
ORDER BY user_identity, event_count DESC
LIMIT 100;

-- Query: active_users - Most Active Users
-- Purpose: Identify power users and understand usage patterns
SELECT 
    COALESCE(
        REGEXP_EXTRACT(user_name, ':(.+)$', 1),
        JSON_EXTRACT_SCALAR(request_parameters, '$.roleSessionName'),
        user_name
    ) as user_identity,
    COUNT(*) as total_actions,
    COUNT(DISTINCT event_name) as unique_actions,
    COUNT(DISTINCT substr(event_time, 1, 10)) as active_days,
    substr(MIN(event_time), 1, 16) as first_activity,
    substr(MAX(event_time), 1, 16) as last_activity,
    COUNT(CASE WHEN error_code IS NOT NULL AND error_code != '' THEN 1 END) as error_count
FROM iam_activity_tracker_database.iam_events
WHERE 
    substr(event_time, 1, 10) >= cast(current_date - INTERVAL '30' DAY as varchar)
    AND user_name != 'unknown'
GROUP BY 
    COALESCE(
        REGEXP_EXTRACT(user_name, ':(.+)$', 1),
        JSON_EXTRACT_SCALAR(request_parameters, '$.roleSessionName'),
        user_name
    )
ORDER BY total_actions DESC
LIMIT 30;

-- =============================================================================
-- 2. PERMISSION AND ROLE QUERIES
-- =============================================================================

-- Query: permission_changes - IAM Permission Modifications
-- Purpose: Track who is modifying IAM permissions
SELECT 
    event_time,
    user_name,
    event_name,
    CASE 
        WHEN request_parameters IS NOT NULL AND request_parameters != 'null' THEN
            CONCAT_WS(' → ',
                NULLIF(JSON_EXTRACT_SCALAR(request_parameters, '$.userName'), ''),
                NULLIF(JSON_EXTRACT_SCALAR(request_parameters, '$.roleName'), ''),
                NULLIF(JSON_EXTRACT_SCALAR(request_parameters, '$.groupName'), ''),
                NULLIF(JSON_EXTRACT_SCALAR(request_parameters, '$.policyName'), ''),
                NULLIF(JSON_EXTRACT_SCALAR(request_parameters, '$.policyArn'), '')
            )
        ELSE 'N/A'
    END as target_resource,
    source_ip,
    error_code
FROM iam_activity_tracker_database.iam_events
WHERE 
    substr(event_time, 1, 10) >= cast(current_date - INTERVAL '90' DAY as varchar)
    AND event_name IN (
        'AttachUserPolicy', 'DetachUserPolicy',
        'AttachGroupPolicy', 'DetachGroupPolicy',
        'AttachRolePolicy', 'DetachRolePolicy',
        'CreateUser', 'DeleteUser',
        'CreateRole', 'DeleteRole',
        'PutUserPolicy', 'DeleteUserPolicy',
        'PutRolePolicy', 'DeleteRolePolicy'
    )
ORDER BY event_time DESC
LIMIT 100;

-- Query: role_assumptions - Role Usage Patterns
-- Purpose: Understand which roles are being used and by whom
SELECT 
    JSON_EXTRACT_SCALAR(request_parameters, '$.roleArn') as role_arn,
    COALESCE(
        REGEXP_EXTRACT(user_name, ':(.+)$', 1),
        JSON_EXTRACT_SCALAR(request_parameters, '$.roleSessionName'),
        user_name
    ) as assumed_by,
    COUNT(*) as total_assumptions,
    COUNT(DISTINCT substr(event_time, 1, 10)) as unique_days,
    substr(MIN(event_time), 1, 16) as first_assumption,
    substr(MAX(event_time), 1, 16) as last_assumption,
    COUNT(CASE WHEN error_code IS NOT NULL AND error_code != '' THEN 1 END) as failed_assumptions
FROM iam_activity_tracker_database.iam_events
WHERE 
    substr(event_time, 1, 10) >= cast(current_date - INTERVAL '90' DAY as varchar)
    AND event_name = 'AssumeRole'
    AND JSON_EXTRACT_SCALAR(request_parameters, '$.roleArn') IS NOT NULL
GROUP BY 
    JSON_EXTRACT_SCALAR(request_parameters, '$.roleArn'),
    COALESCE(
        REGEXP_EXTRACT(user_name, ':(.+)$', 1),
        JSON_EXTRACT_SCALAR(request_parameters, '$.roleSessionName'),
        user_name
    )
ORDER BY total_assumptions DESC
LIMIT 100;

-- =============================================================================
-- 3. ANALYTICS AND REPORTING QUERIES
-- =============================================================================

-- Query: daily_summary - Daily Activity Summary
-- Purpose: Generate daily summaries for compliance reporting
SELECT 
    substr(event_time, 1, 10) as activity_date,
    COUNT(DISTINCT user_name) as unique_users,
    COUNT(*) as total_events,
    COUNT(CASE WHEN error_code IS NOT NULL AND error_code != '' THEN 1 END) as error_events,
    COUNT(DISTINCT event_name) as unique_actions,
    COUNT(CASE WHEN event_name LIKE 'Create%' THEN 1 END) as create_actions,
    COUNT(CASE WHEN event_name LIKE 'Delete%' THEN 1 END) as delete_actions,
    COUNT(CASE WHEN event_name LIKE 'Update%' OR event_name LIKE 'Put%' THEN 1 END) as modify_actions,
    COUNT(CASE WHEN event_name = 'AssumeRole' THEN 1 END) as role_assumptions
FROM iam_activity_tracker_database.iam_events
WHERE 
    substr(event_time, 1, 10) >= cast(current_date - INTERVAL '30' DAY as varchar)
GROUP BY substr(event_time, 1, 10)
ORDER BY activity_date DESC;

-- Query: hourly_activity - Peak Usage Analysis
-- Purpose: Understand peak usage hours for capacity planning
SELECT 
    cast(substr(event_time, 12, 2) as integer) as hour_of_day,
    COUNT(*) as event_count,
    COUNT(DISTINCT user_name) as active_users,
    COUNT(CASE WHEN error_code IS NOT NULL AND error_code != '' THEN 1 END) as error_events,
    ROUND(100.0 * COUNT(CASE WHEN error_code IS NOT NULL AND error_code != '' THEN 1 END) / COUNT(*), 2) as error_rate_pct
FROM iam_activity_tracker_database.iam_events
WHERE substr(event_time, 1, 10) >= cast(current_date - INTERVAL '7' DAY as varchar)
GROUP BY cast(substr(event_time, 12, 2) as integer)
ORDER BY hour_of_day;

-- =============================================================================
-- 4. SSO/IDENTITY CENTER QUERIES
-- =============================================================================

-- Query: sso_permission_sets - SSO Permission Set Management
-- Purpose: Track creation and modification of SSO permission sets
SELECT 
    event_time,
    user_name,
    event_name,
    JSON_EXTRACT_SCALAR(request_parameters, '$.name') as permission_set_name,
    JSON_EXTRACT_SCALAR(request_parameters, '$.sessionDuration') as session_duration,
    JSON_EXTRACT_SCALAR(request_parameters, '$.description') as description,
    aws_region,
    error_code
FROM iam_activity_tracker_database.iam_events
WHERE 
    substr(event_time, 1, 10) >= cast(current_date - INTERVAL '30' DAY as varchar)
    AND event_type = 'sso'  -- Critical: SSO events only
    AND event_name IN ('CreatePermissionSet', 'UpdatePermissionSet')
ORDER BY event_time DESC
LIMIT 100;

-- Query: sso_account_assignments - SSO Account Access Grants
-- Purpose: Track who is getting access to which AWS accounts via SSO
SELECT 
    event_time,
    user_name,
    event_name,
    JSON_EXTRACT_SCALAR(request_parameters, '$.principalId') as principal_id,
    JSON_EXTRACT_SCALAR(request_parameters, '$.principalType') as principal_type,
    JSON_EXTRACT_SCALAR(request_parameters, '$.targetId') as target_account_id,
    JSON_EXTRACT_SCALAR(request_parameters, '$.permissionSetArn') as permission_set_arn,
    aws_region,
    error_code
FROM iam_activity_tracker_database.iam_events
WHERE 
    substr(event_time, 1, 10) >= cast(current_date - INTERVAL '30' DAY as varchar)
    AND event_type = 'sso'  -- Critical: SSO events only
    AND event_name IN ('CreateAccountAssignment', 'DeleteAccountAssignment')
ORDER BY event_time DESC
LIMIT 100;

-- Query: sso_admin_policies - SSO Administrative Policy Attachments
-- Purpose: Track dangerous administrative policy attachments to permission sets
SELECT 
    event_time,
    user_name,
    event_name,
    JSON_EXTRACT_SCALAR(request_parameters, '$.managedPolicyArn') as policy_arn,
    SUBSTR(JSON_EXTRACT_SCALAR(request_parameters, '$.permissionSetArn'), -16) as permission_set_id,
    CASE 
        WHEN JSON_EXTRACT_SCALAR(request_parameters, '$.managedPolicyArn') LIKE '%AdministratorAccess%' THEN 'CRITICAL'
        WHEN JSON_EXTRACT_SCALAR(request_parameters, '$.managedPolicyArn') LIKE '%PowerUserAccess%' THEN 'CRITICAL'
        WHEN JSON_EXTRACT_SCALAR(request_parameters, '$.managedPolicyArn') LIKE '%IAMFullAccess%' THEN 'CRITICAL'
        ELSE 'NORMAL'
    END as risk_level,
    aws_region,
    error_code
FROM iam_activity_tracker_database.iam_events
WHERE 
    substr(event_time, 1, 10) >= cast(current_date - INTERVAL '30' DAY as varchar)
    AND event_type = 'sso'  -- Critical: SSO events only
    AND event_name = 'AttachManagedPolicyToPermissionSet'
ORDER BY event_time DESC
LIMIT 100;

-- Query: sso_applications - SSO Application Management
-- Purpose: Track third-party application integrations and removal
SELECT 
    event_time,
    user_name,
    event_name,
    CASE 
        WHEN event_name = 'CreateManagedApplicationInstance' THEN 
            JSON_EXTRACT_SCALAR(request_parameters, '$.applicationName')
        WHEN event_name = 'DeleteManagedApplicationInstance' THEN 
            JSON_EXTRACT_SCALAR(request_parameters, '$.managedApplicationInstanceId')
        ELSE 
            COALESCE(
                JSON_EXTRACT_SCALAR(request_parameters, '$.applicationArn'),
                JSON_EXTRACT_SCALAR(request_parameters, '$.applicationId')
            )
    END as application_identifier,
    JSON_EXTRACT_SCALAR(request_parameters, '$.status') as status,
    aws_region,
    error_code
FROM iam_activity_tracker_database.iam_events
WHERE 
    substr(event_time, 1, 10) >= cast(current_date - INTERVAL '90' DAY as varchar)
    AND event_type = 'sso'  -- Critical: SSO events only
    AND event_name IN (
        'CreateManagedApplicationInstance',
        'DeleteManagedApplicationInstance',
        'UpdateManagedApplicationInstanceStatus'
    )
ORDER BY event_time DESC
LIMIT 100;

-- Query: sso_admin_users - SSO Administrative Users
-- Purpose: Identify users making dangerous SSO changes
SELECT 
    user_name,
    COUNT(*) as total_admin_actions,
    COUNT(CASE WHEN event_name = 'CreatePermissionSet' THEN 1 END) as permission_sets_created,
    COUNT(CASE WHEN event_name = 'UpdatePermissionSet' THEN 1 END) as permission_sets_updated,
    COUNT(CASE WHEN event_name = 'AttachManagedPolicyToPermissionSet' THEN 1 END) as policies_attached,
    COUNT(CASE WHEN event_name = 'CreateAccountAssignment' THEN 1 END) as assignments_created,
    COUNT(CASE WHEN event_name LIKE '%ManagedApplicationInstance' THEN 1 END) as app_changes,
    COUNT(CASE WHEN error_code IS NOT NULL AND error_code != '' THEN 1 END) as error_count,
    MIN(event_time) as first_admin_action,
    MAX(event_time) as last_admin_action
FROM iam_activity_tracker_database.iam_events
WHERE 
    substr(event_time, 1, 10) >= cast(current_date - INTERVAL '90' DAY as varchar)
    AND event_type = 'sso'  -- Critical: SSO events only
    AND event_name IN (
        'CreatePermissionSet', 'UpdatePermissionSet', 'AttachManagedPolicyToPermissionSet',
        'CreateAccountAssignment', 'CreateManagedApplicationInstance', 'DeleteManagedApplicationInstance'
    )
GROUP BY user_name
ORDER BY total_admin_actions DESC
LIMIT 50;

-- Query: sso_activity_summary - SSO Activity Overview
-- Purpose: Understand SSO usage patterns by event type
SELECT 
    event_name,
    COUNT(*) as event_count,
    COUNT(DISTINCT user_name) as unique_users,
    COUNT(CASE WHEN error_code IS NOT NULL AND error_code != '' THEN 1 END) as error_count,
    ROUND(100.0 * COUNT(CASE WHEN error_code IS NOT NULL AND error_code != '' THEN 1 END) / COUNT(*), 2) as error_rate_pct,
    CASE 
        WHEN event_name IN ('CreatePermissionSet', 'UpdatePermissionSet', 
                           'AttachManagedPolicyToPermissionSet', 'CreateAccountAssignment') THEN 'ADMINISTRATIVE'
        ELSE 'OPERATIONAL'
    END as activity_category
FROM iam_activity_tracker_database.iam_events
WHERE 
    substr(event_time, 1, 10) >= cast(current_date - INTERVAL '30' DAY as varchar)
    AND event_type = 'sso'  -- Critical: SSO events only
GROUP BY event_name
ORDER BY event_count DESC
LIMIT 100;

-- =============================================================================
-- NOTES:
-- =============================================================================
-- 1. All SSO queries MUST include "event_type = 'sso'" filter
-- 2. Uses default: iam_activity_tracker_database.iam_events 
-- 3. These queries are synchronized with query_runner.py
-- 4. For automated execution use: make run-query Q=<query_name>
-- 5. For JSON output add: FORMAT=json
-- 6. Date ranges can be adjusted based on your retention needs