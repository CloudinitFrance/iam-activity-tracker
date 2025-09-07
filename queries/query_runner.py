#!/usr/bin/env python3
"""
IAM Activity Query Runner

Command-line tool and Python library for running pre-built analytics queries
against your IAM activity data in Athena.
"""

import argparse
import json
import os
import sys
import subprocess
from datetime import datetime
from typing import Dict, Any, List

try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from athena_utilities import (
    execute_athena_query, 
    create_iam_events_table,
    get_table_statistics,
    validate_s3_location
)

def get_account_id():
    """Get AWS Account ID from STS"""
    try:
        result = subprocess.run(['aws', 'sts', 'get-caller-identity', '--query', 'Account', '--output', 'text'], 
                              capture_output=True, text=True, check=True)
        account_id = result.stdout.strip()
        if not account_id or account_id == 'None':
            raise Exception("Failed to get AWS Account ID")
        return account_id
    except Exception as e:
        raise Exception(f"Cannot get AWS Account ID. Check AWS CLI and credentials: {e}")

# Configuration
DEFAULT_DATABASE = os.environ.get('ATHENA_DATABASE', 'iam_activity_tracker_database')
DEFAULT_WORKGROUP = os.environ.get('ATHENA_WORKGROUP', 'iam-activity-tracker-workgroup')
DEFAULT_OUTPUT_LOCATION = os.environ.get('ATHENA_OUTPUT_LOCATION', f's3://iam-activity-tracker-athena-results-{get_account_id()}/')
DEFAULT_TABLE_NAME = 'iam_events'

# Pre-built query definitions
QUERY_DEFINITIONS = {
    'user_lookup': {
        'name': 'User Activity Summary',
        'description': 'Identify and analyze user activity patterns',
        'table_query': """
        SELECT 
            COALESCE(
                REGEXP_EXTRACT(user_name, ':(.+)$', 1),
                JSON_EXTRACT_SCALAR(request_parameters, '$.roleSessionName'),
                user_name
            ) as user_identity,
            substr(MIN(event_time), 1, 16) as first_activity,
            substr(MAX(event_time), 1, 16) as last_activity,
            COUNT(*) as total_events
        FROM {database}.{table_name}
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
        LIMIT 25
        """,
        'query': """
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
        FROM {database}.{table_name}
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
        LIMIT 25
        """
    },
    'failed_auth': {
        'name': 'Failed Authentication Attempts',
        'description': 'Identify potential brute force attacks or credential issues',
        'query': """
        SELECT 
            event_date,
            user_name,
            source_ip,
            event_name,
            COALESCE(error_code, error_message) as error,
            COUNT(*) as failure_count
        FROM {database}.{table_name}
        WHERE 
            event_date >= cast(current_date - interval '7' day as varchar)
            AND (
                (error_code IS NOT NULL AND error_code != '') 
                OR (error_message IS NOT NULL AND error_message != '')
            )
            AND (
                event_name IN ('ConsoleLogin', 'AssumeRole', 'GetSessionToken')
                OR event_source = 'signin.amazonaws.com'
            )
        GROUP BY 1, 2, 3, 4, 5
        ORDER BY failure_count DESC, event_date DESC
        LIMIT 100
        """
    },
    'root_usage': {
        'name': 'Root Account Usage Detection',
        'description': 'Alert on any root account activity (security violation)',
        'query': """
        SELECT 
            event_time,
            event_name,
            user_name,
            source_ip,
            user_agent,
            aws_region,
            request_parameters
        FROM {database}.{table_name}
        WHERE 
            substr(event_time, 1, 10) >= cast(current_date - INTERVAL '90' DAY as varchar)
            AND LOWER(user_name) = 'root'
        ORDER BY event_time DESC
        LIMIT 100
        """
    },
    'off_hours': {
        'name': 'Off-Hours Activity',
        'description': 'Detect after-hours access that might indicate compromise',
        'table_query': """
        SELECT 
            COALESCE(
                REGEXP_EXTRACT(user_name, ':(.+)$', 1),
                JSON_EXTRACT_SCALAR(request_parameters, '$.roleSessionName'),
                user_name
            ) as user_identity,
            event_name,
            COUNT(*) as event_count,
            MAX(event_time) as last_occurrence
        FROM {database}.{table_name}
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
        LIMIT 100
        """,
        'query': """
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
        FROM {database}.{table_name}
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
        LIMIT 100
        """
    },
    'active_users': {
        'name': 'Most Active Users',
        'description': 'Identify power users and understand usage patterns',
        'table_query': """
        SELECT 
            COALESCE(
                REGEXP_EXTRACT(user_name, ':(.+)$', 1),
                JSON_EXTRACT_SCALAR(request_parameters, '$.roleSessionName'),
                user_name
            ) as user_identity,
            COUNT(*) as total_actions,
            substr(MIN(event_time), 1, 16) as first_activity,
            substr(MAX(event_time), 1, 16) as last_activity,
            COUNT(CASE WHEN error_code IS NOT NULL AND error_code != '' THEN 1 END) as error_count
        FROM {database}.{table_name}
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
        LIMIT 30
        """,
        'query': """
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
        FROM {database}.{table_name}
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
        LIMIT 30
        """
    },
    'permission_changes': {
        'name': 'Permission Changes',
        'description': 'Track who is modifying IAM permissions',
        'query': """
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
        FROM {database}.{table_name}
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
        LIMIT 100
        """
    },
    'role_assumptions': {
        'name': 'Role Assumption Patterns',
        'description': 'Understand which roles are being used and by whom',
        'query': """
        SELECT 
            CASE 
                WHEN JSON_EXTRACT_SCALAR(request_parameters, '$.roleArn') IS NOT NULL 
                THEN regexp_extract(JSON_EXTRACT_SCALAR(request_parameters, '$.roleArn'), 'role/([^/]+)$', 1)
                ELSE 'unknown'
            END as role_name,
            CASE 
                WHEN user_name = 'unknown' THEN 
                    COALESCE(
                        REPLACE(user_agent, '.amazonaws.com', ''),
                        JSON_EXTRACT_SCALAR(request_parameters, '$.roleSessionName'),
                        'AWS Service'
                    )
                WHEN LENGTH(user_name) > 20 THEN CONCAT(SUBSTR(user_name, 1, 15), '...')
                WHEN POSITION(':' IN user_name) > 0 THEN regexp_extract(user_name, ':(.*)', 1)
                ELSE user_name
            END as assumed_by,
            COUNT(*) as assumption_count,
            COUNT(CASE WHEN error_code IS NOT NULL AND error_code != '' THEN 1 END) as failed_assumptions
        FROM {database}.{table_name}
        WHERE 
            substr(event_time, 1, 10) >= cast(current_date - INTERVAL '90' DAY as varchar)
            AND event_name = 'AssumeRole'
            AND JSON_EXTRACT_SCALAR(request_parameters, '$.roleArn') IS NOT NULL
        GROUP BY 1, 2
        HAVING COUNT(*) > 5
        ORDER BY assumption_count DESC
        LIMIT 50
        """
    },
    'daily_summary': {
        'name': 'Daily Activity Summary',
        'description': 'Generate daily summaries for compliance reporting',
        'query': """
        SELECT 
            substr(event_time, 1, 10) as activity_date,
            COUNT(*) as total_events,
            COUNT(DISTINCT user_name) as unique_users,
            COUNT(DISTINCT event_name) as unique_actions,
            COUNT(CASE WHEN error_code IS NOT NULL AND error_code != '' THEN 1 END) as failed_events,
            COUNT(CASE WHEN LOWER(event_name) LIKE '%create%' AND LOWER(event_name) LIKE '%user%' THEN 1 END) as users_created,
            COUNT(CASE WHEN LOWER(event_name) LIKE '%delete%' AND LOWER(event_name) LIKE '%user%' THEN 1 END) as users_deleted,
            COUNT(CASE WHEN LOWER(event_name) LIKE '%policy%' THEN 1 END) as policy_changes,
            COUNT(CASE WHEN LOWER(event_name) LIKE '%assume%' THEN 1 END) as role_assumptions
        FROM {database}.{table_name}
        WHERE substr(event_time, 1, 10) >= cast(current_date - INTERVAL '90' DAY as varchar)
        GROUP BY substr(event_time, 1, 10)
        ORDER BY activity_date DESC
        LIMIT 30
        """
    },
    'hourly_activity': {
        'name': 'Hourly Activity Distribution',
        'description': 'Understand peak usage hours for capacity planning',
        'query': """
        SELECT 
            cast(substr(event_time, 12, 2) as integer) as hour_of_day,
            COUNT(*) as total_events,
            COUNT(DISTINCT user_name) as active_users,
            COUNT(CASE WHEN error_code IS NOT NULL AND error_code != '' THEN 1 END) as error_events,
            ROUND(100.0 * COUNT(CASE WHEN error_code IS NOT NULL AND error_code != '' THEN 1 END) / COUNT(*), 2) as error_rate_pct
        FROM {database}.{table_name}
        WHERE substr(event_time, 1, 10) >= cast(current_date - INTERVAL '7' DAY as varchar)
        GROUP BY cast(substr(event_time, 12, 2) as integer)
        ORDER BY hour_of_day
        """
    },
    'sso_permission_sets': {
        'name': 'SSO Permission Set Management',
        'description': 'Track creation and modification of SSO permission sets',
        'query': """
        SELECT 
            event_time,
            user_name,
            event_name,
            JSON_EXTRACT_SCALAR(request_parameters, '$.name') as permission_set_name,
            JSON_EXTRACT_SCALAR(request_parameters, '$.description') as description,
            aws_region,
            error_code
        FROM {database}.{table_name}
        WHERE 
            substr(event_time, 1, 10) >= cast(current_date - INTERVAL '30' DAY as varchar)
            AND event_type = 'sso'
            AND event_name IN ('CreatePermissionSet', 'UpdatePermissionSet')
        ORDER BY event_time DESC
        LIMIT 100
        """
    },
    'sso_account_assignments': {
        'name': 'SSO Account Assignments',
        'description': 'Track who is getting access to which AWS accounts via SSO',
        'table_query': """
        SELECT 
            user_name,
            event_name,
            REGEXP_REPLACE(JSON_EXTRACT_SCALAR(request_parameters, '$.targetId'), '[^0-9]', '') as account_id,
            CONCAT('ps-', SUBSTR(JSON_EXTRACT_SCALAR(request_parameters, '$.permissionSetArn'), -16)) as permission_set,
            event_time
        FROM {database}.{table_name}
        WHERE 
            substr(event_time, 1, 10) >= cast(current_date - INTERVAL '30' DAY as varchar)
            AND event_type = 'sso'
            AND event_name IN ('CreateAccountAssignment', 'DeleteAccountAssignment')
        ORDER BY event_time DESC
        LIMIT 100
        """,
        'json_query': """
        SELECT 
            event_time,
            user_name,
            event_name,
            JSON_EXTRACT_SCALAR(request_parameters, '$.principalId') as principal_id,
            JSON_EXTRACT_SCALAR(request_parameters, '$.principalType') as principal_type,
            JSON_EXTRACT_SCALAR(request_parameters, '$.targetId') as target_account_id,
            JSON_EXTRACT_SCALAR(request_parameters, '$.permissionSetArn') as permission_set_arn,
            request_parameters,
            response_elements,
            aws_region,
            source_ip,
            user_agent,
            error_code,
            error_message
        FROM {database}.{table_name}
        WHERE 
            substr(event_time, 1, 10) >= cast(current_date - INTERVAL '30' DAY as varchar)
            AND event_type = 'sso'
            AND event_name IN ('CreateAccountAssignment', 'DeleteAccountAssignment')
        ORDER BY event_time DESC
        LIMIT 100
        """
    },
    'sso_admin_policies': {
        'name': 'SSO Admin Policy Attachments',
        'description': 'Track dangerous administrative policy attachments to permission sets',
        'table_query': """
        SELECT 
            user_name,
            REGEXP_EXTRACT(JSON_EXTRACT_SCALAR(request_parameters, '$.managedPolicyArn'), '[^/]+$') as policy,
            CONCAT('ps-', SUBSTR(JSON_EXTRACT_SCALAR(request_parameters, '$.permissionSetArn'), -16)) as permission_set,
            event_time
        FROM {database}.{table_name}
        WHERE 
            substr(event_time, 1, 10) >= cast(current_date - INTERVAL '30' DAY as varchar)
            AND event_type = 'sso'
            AND event_name = 'AttachManagedPolicyToPermissionSet'
        ORDER BY event_time DESC
        LIMIT 100
        """,
        'query': """
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
        FROM {database}.{table_name}
        WHERE 
            substr(event_time, 1, 10) >= cast(current_date - INTERVAL '30' DAY as varchar)
            AND event_type = 'sso'
            AND event_name = 'AttachManagedPolicyToPermissionSet'
        ORDER BY event_time DESC
        LIMIT 100
        """
    },
    'sso_applications': {
        'name': 'SSO Application Management',
        'description': 'Track third-party application integrations and removal',
        'query': """
        SELECT 
            event_time,
            user_name,
            event_name,
            CASE 
                WHEN JSON_EXTRACT_SCALAR(request_parameters, '$.displayName') = 'HIDDEN_DUE_TO_SECURITY_REASONS' 
                THEN 'Unknown Application'
                ELSE JSON_EXTRACT_SCALAR(request_parameters, '$.displayName')
            END as application_name,
            JSON_EXTRACT_SCALAR(request_parameters, '$.templateId') as template_id,
            JSON_EXTRACT_SCALAR(request_parameters, '$.startUrl') as start_url,
            JSON_EXTRACT_SCALAR(request_parameters, '$.clientId') as client_id,
            aws_region,
            error_code
        FROM {database}.{table_name}
        WHERE 
            substr(event_time, 1, 10) >= cast(current_date - INTERVAL '30' DAY as varchar)
            AND event_type = 'sso'
            AND event_name IN ('CreateManagedApplicationInstance', 'DeleteManagedApplicationInstance')
        ORDER BY event_time DESC
        LIMIT 100
        """
    },
    'sso_admin_users': {
        'name': 'SSO Administrative Users',
        'description': 'Identify users making dangerous SSO changes',
        'table_query': """
        SELECT 
            user_name,
            COUNT(*) as total_admin_actions,
            COUNT(CASE WHEN event_name = 'CreatePermissionSet' THEN 1 END) as permission_sets_created,
            COUNT(CASE WHEN event_name = 'UpdatePermissionSet' THEN 1 END) as permission_sets_updated,
            COUNT(CASE WHEN event_name = 'AttachManagedPolicyToPermissionSet' THEN 1 END) as policies_attached,
            COUNT(CASE WHEN event_name = 'CreateAccountAssignment' THEN 1 END) as assignments_created,
            COUNT(CASE WHEN event_name LIKE '%ManagedApplicationInstance' THEN 1 END) as app_changes,
            COUNT(CASE WHEN error_code IS NOT NULL AND error_code != '' THEN 1 END) as error_count,
            MAX(event_time) as last_admin_action
        FROM {database}.{table_name}
        WHERE 
            substr(event_time, 1, 10) >= cast(current_date - INTERVAL '90' DAY as varchar)
            AND event_type = 'sso'
            AND event_name IN (
                'CreatePermissionSet', 'UpdatePermissionSet', 'AttachManagedPolicyToPermissionSet',
                'CreateAccountAssignment', 'CreateManagedApplicationInstance', 'DeleteManagedApplicationInstance'
            )
        GROUP BY user_name
        ORDER BY total_admin_actions DESC
        LIMIT 50
        """,
        'query': """
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
        FROM {database}.{table_name}
        WHERE 
            substr(event_time, 1, 10) >= cast(current_date - INTERVAL '90' DAY as varchar)
            AND event_type = 'sso'
            AND event_name IN (
                'CreatePermissionSet', 'UpdatePermissionSet', 'AttachManagedPolicyToPermissionSet',
                'CreateAccountAssignment', 'CreateManagedApplicationInstance', 'DeleteManagedApplicationInstance'
            )
        GROUP BY user_name
        ORDER BY total_admin_actions DESC
        LIMIT 50
        """
    },
    'sso_activity_summary': {
        'name': 'SSO Activity Overview',
        'description': 'Understand SSO usage patterns by event type',
        'query': """
        SELECT 
            event_name,
            COUNT(*) as event_count,
            COUNT(DISTINCT user_name) as unique_users,
            COUNT(CASE WHEN error_code IS NOT NULL AND error_code != '' THEN 1 END) as error_count,
            ROUND(100.0 * COUNT(CASE WHEN error_code IS NOT NULL AND error_code != '' THEN 1 END) / COUNT(*), 2) as error_rate_pct,
            CASE 
                WHEN event_name IN ('CreatePermissionSet', 'UpdatePermissionSet', 'CreateAccountAssignment', 'AttachManagedPolicyToPermissionSet') THEN 'ADMINISTRATIVE'
                WHEN event_name IN ('CreateManagedApplicationInstance', 'DeleteManagedApplicationInstance') THEN 'APPLICATION_MGMT'
                ELSE 'OPERATIONAL'
            END as activity_category
        FROM {database}.{table_name}
        WHERE 
            substr(event_time, 1, 10) >= cast(current_date - INTERVAL '30' DAY as varchar)
            AND event_type = 'sso'
        GROUP BY event_name
        ORDER BY event_count DESC
        LIMIT 20
        """
    }
}


def run_query(
    query_name: str,
    database: str = DEFAULT_DATABASE,
    table_name: str = DEFAULT_TABLE_NAME,
    workgroup: str = DEFAULT_WORKGROUP,
    output_location: str = DEFAULT_OUTPUT_LOCATION,
    output_format: str = 'table'
) -> Dict[str, Any]:
    """
    Run a pre-built query by name.
    
    Args:
        query_name: Name of the query to run
        database: Athena database name
        table_name: Table name
        workgroup: Athena workgroup
        output_location: S3 location for results
        
    Returns:
        dict: Query results
    """
    if query_name not in QUERY_DEFINITIONS:
        raise ValueError(f"Unknown query: {query_name}. Available queries: {list(QUERY_DEFINITIONS.keys())}")
    
    query_def = QUERY_DEFINITIONS[query_name]
    
    # Choose the appropriate query based on format
    if output_format == 'json' and 'json_query' in query_def:
        query_template = query_def['json_query']
    elif 'table_query' in query_def:
        query_template = query_def['table_query']
    else:
        # Backward compatibility for queries that haven't been updated yet
        query_template = query_def.get('query', query_def.get('table_query'))
    
    query = query_template.format(
        database=database,
        table_name=table_name
    )
    
    if RICH_AVAILABLE:
        console = Console()
        console.print(f"[bold blue]Running query:[/bold blue] {query_def['name']}")
        console.print(f"[dim]{query_def['description']}[/dim]")
        console.print()
    else:
        print(f"Running query: {query_def['name']}")
        print(f"Description: {query_def['description']}")
        print()
    
    return execute_athena_query(
        query=query,
        database=database,
        workgroup=workgroup,
        output_location=output_location
    )


def list_available_queries() -> None:
    """Print all available pre-built queries."""
    if RICH_AVAILABLE:
        console = Console()
        
        # Create a table for available queries
        table = Table(
            title="[bold blue]Available IAM Activity Queries[/bold blue]",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
            expand=True
        )
        
        table.add_column("Query Name", style="green bold", no_wrap=True)
        table.add_column("Description", style="white")
        table.add_column("Usage", style="yellow", no_wrap=True)
        
        # Add rows for each query
        for query_name, query_def in QUERY_DEFINITIONS.items():
            table.add_row(
                query_name,
                query_def['description'],
                f"python query_runner.py run {query_name}"
            )
        
        console.print(table)
        console.print(f"\n[dim]Total: {len(QUERY_DEFINITIONS)} queries available[/dim]")
        
    else:
        # Fallback for when Rich is not available
        print("Available Pre-built Queries:")
        print("=" * 50)
        
        for query_name, query_def in QUERY_DEFINITIONS.items():
            print(f"\n{query_name}:")
            print(f"  Name: {query_def['name']}")
            print(f"  Description: {query_def['description']}")
            print(f"  Usage: python query_runner.py run {query_name}")


def setup_table(
    database: str,
    table_name: str,
    s3_location: str,
    workgroup: str,
    output_location: str
) -> Dict[str, Any]:
    """
    Set up the Athena table for IAM events.
    
    Args:
        database: Athena database name
        table_name: Table name to create
        s3_location: S3 location of Parquet files
        workgroup: Athena workgroup
        output_location: S3 location for query results
        
    Returns:
        dict: Setup result
    """
    print(f"Setting up Athena table: {database}.{table_name}")
    print(f"Data location: {s3_location}")
    
    # Validate S3 location
    if not validate_s3_location(s3_location):
        return {
            'status': 'error',
            'error': f'S3 location {s3_location} is not accessible or contains no data'
        }
    
    # Create table
    result = create_iam_events_table(
        database=database,
        table_name=table_name,
        s3_location=s3_location,
        workgroup=workgroup,
        output_location=output_location
    )
    
    if result['status'] == 'success':
        print("Table created successfully")
        
        # Get table statistics
        print("Getting table statistics...")
        stats_result = get_table_statistics(database, table_name, workgroup, output_location)
        if stats_result['status'] == 'success' and stats_result['results']:
            stats = stats_result['results'][0]
            print(f"Table Statistics:")
            print(f"  Total Events: {stats.get('total_events', 'N/A')}")
            print(f"  Unique Users: {stats.get('unique_users', 'N/A')}")
            print(f"  Date Range: {stats.get('earliest_event', 'N/A')} to {stats.get('latest_event', 'N/A')}")
        else:
            print(f"Warning: Statistics query failed: {stats_result.get('error', 'Unknown error')}")
            print("Info: Table created successfully but statistics unavailable")
    else:
        print(f"Error: Table creation failed: {result.get('error', 'Unknown error')}")
    
    return result


def export_results_to_json(results: Dict[str, Any], output_file: str) -> None:
    """Export query results to JSON file."""
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"Results exported to: {output_file}")


def format_results_table(results: List[Dict[str, Any]], max_rows: int = 20) -> str:
    """Format query results as a beautiful table using Rich library."""
    if not results:
        return "No results found."
    
    if not RICH_AVAILABLE:
        return format_simple_table(results, max_rows)
    
    console = Console()
    
    # Create Rich table
    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold blue",
        show_lines=True,
        expand=True
    )
    
    # Get column names
    columns = list(results[0].keys())
    
    # Add columns with styling
    for col in columns:
        if 'count' in col.lower() or 'days' in col.lower():
            # Numeric columns - right aligned, green
            table.add_column(col.replace('_', ' ').title(), justify="right", style="green", no_wrap=True)
        elif 'arn' in col.lower():
            # ARN columns - truncated, cyan
            table.add_column(col.replace('_', ' ').title(), style="dim", max_width=60)
        elif 'role_name' in col.lower():
            # Role name - cyan, bold
            table.add_column(col.replace('_', ' ').title(), style="cyan bold", no_wrap=True)
        elif ('user' in col.lower() or 'display' in col.lower() or 'assumed_by' in col.lower()) and 'agent' not in col.lower():
            # User name - yellow (but not user_agent)
            table.add_column(col.replace('_', ' ').title(), style="yellow", no_wrap=True)
        elif 'error' in col.lower() or 'fail' in col.lower():
            # Error columns - red
            table.add_column(col.replace('_', ' ').title(), justify="right", style="red")
        elif 'time' in col.lower() or 'date' in col.lower():
            # Time/date columns - blue
            table.add_column(col.replace('_', ' ').title(), style="blue")
        elif 'ip' in col.lower() or 'address' in col.lower():
            # IP address columns - magenta
            table.add_column(col.replace('_', ' ').title(), style="magenta")
        elif 'region' in col.lower():
            # Region columns - green
            table.add_column(col.replace('_', ' ').title(), style="green")
        elif 'event_name' in col.lower() or 'action' in col.lower():
            # Event name columns - cyan bold
            table.add_column(col.replace('_', ' ').title(), style="cyan bold")
        elif 'target_resource' in col.lower() or 'resource' in col.lower():
            # Target resource columns - no width limit, allow wrapping
            table.add_column(col.replace('_', ' ').title(), style="green", no_wrap=False, overflow="fold")
        else:
            # Default styling
            table.add_column(col.replace('_', ' ').title())
    
    # Add rows with styling
    rows_shown = min(len(results), max_rows)
    for i, row in enumerate(results[:max_rows]):
        formatted_row = []
        for col in columns:
            value = row.get(col, '')
            
            # Format specific column types
            if 'arn' in col.lower() and str(value).startswith('arn:'):
                # Truncate ARN to show just the role name part
                if '/role/' in str(value):
                    role_part = str(value).split('/role/')[-1]
                    formatted_row.append(f".../{role_part}")
                else:
                    formatted_row.append(str(value)[-35:] if len(str(value)) > 35 else str(value))
            elif 'user_name' in col.lower() and str(value) == 'unknown':
                # Style unknown values
                formatted_row.append("[dim]unknown[/dim]")
            elif 'time' in col.lower() or 'date' in col.lower():
                # Format timestamps more readably
                if str(value) and len(str(value)) > 10:
                    # Parse and format datetime
                    try:
                        from datetime import datetime
                        if 'T' in str(value):
                            dt = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
                            formatted_row.append(dt.strftime('%Y-%m-%d %H:%M'))
                        else:
                            formatted_row.append(str(value))
                    except:
                        formatted_row.append(str(value))
                else:
                    formatted_row.append(str(value))
            elif ('count' in col.lower() and 'account' not in col.lower()) or 'days' in col.lower():
                # Format numbers with commas (but not account IDs)
                if str(value).isdigit():
                    formatted_row.append(f"{int(value):,}")
                else:
                    formatted_row.append(str(value))
            elif 'error' in col.lower() or 'fail' in col.lower():
                # Highlight non-zero errors
                if str(value) != '0' and str(value) != '':
                    formatted_row.append(f"[bold red]{value}[/bold red]")
                else:
                    formatted_row.append(str(value))
            else:
                formatted_row.append(str(value))
        
        table.add_row(*formatted_row)
    
    # Capture the table as string
    with console.capture() as capture:
        console.print(table)
        if len(results) > max_rows:
            console.print(f"\n[dim]... and {len(results) - max_rows} more rows[/dim]", style="italic")
        
        # Add summary statistics
        if 'assumption_count' in columns:
            total_assumptions = sum(int(row.get('assumption_count', 0)) for row in results)
            unique_roles = len(set(row.get('role_name', '') for row in results))
            console.print(f"\n[bold]Summary:[/bold] {len(results)} roles, {total_assumptions:,} total assumptions", style="blue")
    
    return capture.get()


def format_simple_table(results: List[Dict[str, Any]], max_rows: int = 20) -> str:
    """Fallback simple table formatting when Rich is not available."""
    if not results:
        return "No results found."
    
    # Get column names
    columns = list(results[0].keys())
    
    # Calculate column widths
    col_widths = {}
    for col in columns:
        col_widths[col] = max(len(col), max(len(str(row.get(col, ''))) for row in results[:max_rows]))
    
    # Build table
    output = []
    
    # Header
    header = " | ".join(col.ljust(col_widths[col]) for col in columns)
    output.append(header)
    output.append("-" * len(header))
    
    # Rows
    for i, row in enumerate(results[:max_rows]):
        row_str = " | ".join(str(row.get(col, '')).ljust(col_widths[col]) for col in columns)
        output.append(row_str)
    
    if len(results) > max_rows:
        output.append(f"... ({len(results) - max_rows} more rows)")
    
    return "\n".join(output)


def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(
        description='IAM Activity Analytics Query Runner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python query_runner.py list
  python query_runner.py run failed_auth
  python query_runner.py run active_users --database my_database
  python query_runner.py setup --s3-location s3://my-bucket/iam-events/
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # List command
    subparsers.add_parser('list', help='List available queries')
    
    # Run command
    run_parser = subparsers.add_parser('run', help='Run a pre-built query')
    run_parser.add_argument('query_name', help='Name of the query to run')
    run_parser.add_argument('--database', default=DEFAULT_DATABASE, help='Athena database name')
    run_parser.add_argument('--table', default=DEFAULT_TABLE_NAME, help='Table name')
    run_parser.add_argument('--workgroup', default=DEFAULT_WORKGROUP, help='Athena workgroup')
    run_parser.add_argument('--output-location', default=DEFAULT_OUTPUT_LOCATION, help='S3 output location')
    run_parser.add_argument('--export-json', help='Export results to JSON file')
    run_parser.add_argument('--max-rows', type=int, default=20, help='Maximum rows to display')
    run_parser.add_argument('--format', choices=['table', 'json'], default='table', 
                          help='Output format: table (default, curated fields) or json (all fields)')
    
    # Setup command
    setup_parser = subparsers.add_parser('setup', help='Set up Athena table')
    setup_parser.add_argument('--database', default=DEFAULT_DATABASE, help='Athena database name')
    setup_parser.add_argument('--table', default=DEFAULT_TABLE_NAME, help='Table name')
    setup_parser.add_argument('--s3-location', required=True, help='S3 location of Parquet files')
    setup_parser.add_argument('--workgroup', default=DEFAULT_WORKGROUP, help='Athena workgroup')
    setup_parser.add_argument('--output-location', default=DEFAULT_OUTPUT_LOCATION, help='S3 output location')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    if args.command == 'list':
        list_available_queries()
    
    elif args.command == 'setup':
        result = setup_table(
            database=args.database,
            table_name=args.table,
            s3_location=args.s3_location,
            workgroup=args.workgroup,
            output_location=args.output_location
        )
        
        if result['status'] != 'success':
            print(f"Setup failed: {result.get('error')}")
            sys.exit(1)
    
    elif args.command == 'run':
        try:
            result = run_query(
                query_name=args.query_name,
                database=args.database,
                table_name=args.table,
                workgroup=args.workgroup,
                output_location=args.output_location,
                output_format=args.format
            )
            
            if result['status'] == 'success':
                print(f"Query completed successfully")
                print(f"Execution time: {result.get('execution_time_ms', 0)}ms")
                print(f"Data scanned: {result.get('data_scanned_mb', 0):.2f}MB")
                print(f"Estimated cost: ${result.get('cost_estimate_usd', 0):.4f}")
                print(f"Results: {len(result['results'])} rows")
                print()
                
                # Display results
                if result['results']:
                    if args.format == 'json':
                        # JSON output - pretty printed
                        import json
                        print(json.dumps(result['results'], indent=2, default=str))
                    else:
                        # Table output - formatted table
                        print(format_results_table(result['results'], args.max_rows))
                else:
                    print("No results found.")
                
                # Export if requested
                if args.export_json:
                    export_results_to_json(result, args.export_json)
                    
            else:
                print(f"Error: Query failed: {result.get('error')}")
                sys.exit(1)
                
        except Exception as e:
            print(f"Error running query: {e}")
            sys.exit(1)


if __name__ == '__main__':
    main()