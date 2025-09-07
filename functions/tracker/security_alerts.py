"""
Security Alerts Module

Monitors IAM/STS/Signin events for suspicious activity and sends SNS notifications.
"""

import json
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Environment variables
SNS_TOPIC_ARN = os.environ.get('ALERTS_SNS_TOPIC_ARN')
ALERTS_ENABLED = os.environ.get('ALERTS_ENABLED', 'true').lower() == 'true'
ALERTS_TABLE_NAME = os.environ.get('ALERTS_TABLE_NAME')
ACCOUNT_ID = os.environ.get('AWS_ACCOUNT_ID', '')

# Initialize AWS clients
sns_client = boto3.client('sns') if ALERTS_ENABLED and SNS_TOPIC_ARN else None
dynamodb = boto3.resource('dynamodb') if ALERTS_ENABLED and ALERTS_TABLE_NAME else None
alerts_table = dynamodb.Table(ALERTS_TABLE_NAME) if dynamodb and ALERTS_TABLE_NAME else None

# Alert types
class AlertType:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    WARNING = "WARNING"

# Admin policy ARNs to detect
ADMIN_POLICY_ARNS = [
    'AdministratorAccess',
    'IAMFullAccess', 
    'PowerUserAccess',
    'AWSSSOMasterAccountAdministrator',
    'AWSIdentityCenterFullAccess',
    'AWSSSOMemberAccountAdministrator'
]


def _parse_request_parameters(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Safe parsing of request_parameters JSON.
    
    Args:
        event: Event dictionary containing request_parameters
        
    Returns:
        dict: Parsed request parameters or empty dict if parsing fails
    """
    try:
        return json.loads(event.get('request_parameters', '{}'))
    except Exception as e:
        logger.error(f"Error parsing request_parameters for {event.get('event_name', 'unknown')}: {e}")
        return {}


def _create_alert(alert_type: str, title: str, message: str) -> Dict[str, Any]:
    """
    Create standardized alert dictionary.
    
    Args:
        alert_type: Alert severity (CRITICAL, HIGH, WARNING)
        title: Alert title
        message: Alert message
        
    Returns:
        dict: Standardized alert dictionary
    """
    return {
        'type': alert_type,
        'title': title,
        'message': message
    }


def should_check_alerts(event: Dict[str, Any]) -> bool:
    """
    Determine if this event should be checked for alerts.
    
    Args:
        event: Transformed event from handler
        
    Returns:
        bool: True if alerts should be checked
    """
    if not ALERTS_ENABLED or not SNS_TOPIC_ARN or not alerts_table:
        return False
    
    # Don't alert on AWS service events
    if event.get('user_name') == 'unknown':
        return False
    
    # Must have event_id for deduplication
    if not event.get('event_id'):
        logger.warning("Event missing event_id, cannot check alerts")
        return False
    
    return True


def check_root_activity(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Check for root account activity.
    Triggers: Root Account Login (CRITICAL), Failed root login (CRITICAL)
    
    Args:
        event: Event to check
        
    Returns:
        Alert dict if suspicious, None otherwise
    """
    if event.get('user_name') == 'root' and event.get('event_name') == 'ConsoleLogin':
        if event.get('error_message'):
            return _create_alert(
                AlertType.CRITICAL,
                'Failed Root Login',
                f"Failed root login attempt from IP: {event.get('source_ip')}"
            )
        else:
            return _create_alert(
                AlertType.CRITICAL,
                'Root Account Login',
                f"Root account logged in from IP: {event.get('source_ip')}"
            )
    
    return None


def check_user_creation(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Check for IAM user creation.
    Trigger: User creates IAM user (HIGH)
    
    Args:
        event: Event to check
        
    Returns:
        Alert dict if suspicious, None otherwise
    """
    if event.get('event_name') == 'CreateUser':
        request_params = _parse_request_parameters(event)
        if request_params:
            new_user = request_params.get('userName', 'unknown')
            return _create_alert(
                AlertType.HIGH,
                'IAM User Created',
                f"New IAM user '{new_user}' created by {event.get('user_name')}"
            )
    
    return None


def check_admin_policy_attachment(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Check for admin policy attachments.
    Triggers: Attach AdministratorAccess to user (CRITICAL)
    
    Args:
        event: Event to check
        
    Returns:
        Alert dict if suspicious, None otherwise
    """
    if event.get('event_name') == 'AttachUserPolicy':
        request_params = _parse_request_parameters(event)
        if request_params:
            policy_arn = request_params.get('policyArn', '')
            user_name = request_params.get('userName', 'unknown')
            
            # Check for admin policies
            for admin_policy in ADMIN_POLICY_ARNS:
                if admin_policy in policy_arn:
                    return _create_alert(
                        AlertType.CRITICAL,
                        'Admin Policy Attached',
                        f"Admin policy {admin_policy} attached to user '{user_name}' by {event.get('user_name')}"
                    )
    
    return None


def check_dangerous_inline_policy(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Check for dangerous inline policies.
    Triggers: Attach "*:*" to user (CRITICAL), Attach "iam:*" to user (CRITICAL), Attach "sts:*" to user (CRITICAL)
    
    Args:
        event: Event to check
        
    Returns:
        Alert dict if suspicious, None otherwise
    """
    if event.get('event_name') == 'PutUserPolicy':
        request_params = _parse_request_parameters(event)
        if request_params:
            policy_doc = request_params.get('policyDocument', '')
            policy_name = request_params.get('policyName', 'unknown')
            user_name = request_params.get('userName', 'unknown')
            
            # Parse policy document
            try:
                policy_json = json.loads(policy_doc) if policy_doc else {}
                
                for statement in policy_json.get('Statement', []):
                    if statement.get('Effect') == 'Allow':
                        actions = statement.get('Action', [])
                        # Handle both string and list formats
                        if isinstance(actions, str):
                            actions = [actions]
                        
                        for action in actions:
                            if action == '*':
                                return _create_alert(
                                    AlertType.CRITICAL,
                                    'Full Admin Policy Attached',
                                    f"Policy '{policy_name}' with full admin (*:*) permissions attached to user '{user_name}' by {event.get('user_name')}"
                                )
                            elif action == 'iam:*':
                                return _create_alert(
                                    AlertType.CRITICAL,
                                    'Full IAM Permissions Attached',
                                    f"Policy '{policy_name}' with full IAM permissions attached to user '{user_name}' by {event.get('user_name')}"
                                )
                            elif action == 'sts:*':
                                return _create_alert(
                                    AlertType.CRITICAL,
                                    'Full STS Permissions Attached',
                                    f"Policy '{policy_name}' with full STS permissions attached to user '{user_name}' by {event.get('user_name')}"
                                )
            except Exception as e:
                logger.error(f"Error parsing policy document for PutUserPolicy: {e}")
    
    return None


def check_access_key_creation(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Check for access key creation.
    Trigger: CreateAccessKey (CRITICAL)
    
    Args:
        event: Event to check
        
    Returns:
        Alert dict if suspicious, None otherwise
    """
    if event.get('event_name') == 'CreateAccessKey':
        request_params = _parse_request_parameters(event)
        user_name = request_params.get('userName', event.get('user_name'))
        
        return _create_alert(
            AlertType.CRITICAL,
            'Access Key Created',
            f"New access key created for user '{user_name}' by {event.get('user_name')}"
        )
    
    return None


def check_role_trust_policy(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Check for dangerous role trust policies.
    Triggers: CreateRole with external account or * principal (CRITICAL),
              UpdateAssumeRolePolicy adding external account (CRITICAL)
    
    Args:
        event: Event to check
        
    Returns:
        Alert dict if suspicious, None otherwise
    """
    if event.get('event_name') in ['CreateRole', 'UpdateAssumeRolePolicy']:
        request_params = _parse_request_parameters(event)
        if request_params:
            role_name = request_params.get('roleName', 'unknown')
            
            # Get the trust policy document
            if event.get('event_name') == 'CreateRole':
                policy_doc = request_params.get('assumeRolePolicyDocument', '')
            else:  # UpdateAssumeRolePolicy
                policy_doc = request_params.get('policyDocument', '')
            
            # Parse policy document
            try:
                policy_json = json.loads(policy_doc) if policy_doc else {}
                
                for statement in policy_json.get('Statement', []):
                    if statement.get('Effect') == 'Allow':
                        principal = statement.get('Principal', {})
                        
                        # Check for wildcard principal
                        if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                            return _create_alert(
                                AlertType.CRITICAL,
                                'Role Trust Policy with Wildcard Principal',
                                f"Role '{role_name}' created/updated with trust policy allowing ANY principal by {event.get('user_name')}"
                            )
                        
                        # Check for external account
                        if isinstance(principal, dict) and 'AWS' in principal:
                            aws_principals = principal['AWS']
                            if isinstance(aws_principals, str):
                                aws_principals = [aws_principals]
                            
                            for arn in aws_principals:
                                if ':root' in arn and ACCOUNT_ID:
                                    # Extract account ID from ARN
                                    account_match = arn.split(':')[4] if ':' in arn else None
                                    if account_match and account_match != ACCOUNT_ID:
                                        return _create_alert(
                                            AlertType.CRITICAL,
                                            'Role Trust Policy with External Account',
                                            f"Role '{role_name}' allows access from external account {account_match} - modified by {event.get('user_name')}"
                                        )
            except Exception as e:
                logger.error(f"Error parsing trust policy document: {e}")
    
    return None


def check_access_key_update(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Check for access key updates.
    Trigger: UpdateAccessKey (HIGH)
    
    Args:
        event: Event to check
        
    Returns:
        Alert dict if suspicious, None otherwise
    """
    if event.get('event_name') == 'UpdateAccessKey':
        request_params = _parse_request_parameters(event)
        if request_params:
            user_name = request_params.get('userName', 'unknown')
            status = request_params.get('status', 'unknown')
            access_key_id = request_params.get('accessKeyId', 'unknown')
            
            return _create_alert(
                AlertType.HIGH,
                'Access Key Updated',
                f"Access key {access_key_id[-4:]} for user '{user_name}' changed to {status} by {event.get('user_name')}"
            )
    
    return None


def check_mfa_deletion(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Check for MFA device deletion/deactivation.
    Triggers: DeleteVirtualMFADevice (CRITICAL), DeactivateMFADevice (CRITICAL)
    
    Args:
        event: Event to check
        
    Returns:
        Alert dict if suspicious, None otherwise
    """
    if event.get('event_name') in ['DeleteVirtualMFADevice', 'DeactivateMFADevice']:
        request_params = _parse_request_parameters(event)
        if request_params:
            if event.get('event_name') == 'DeleteVirtualMFADevice':
                serial = request_params.get('serialNumber', 'unknown')
                return _create_alert(
                    AlertType.CRITICAL,
                    'MFA Device Deleted',
                    f"Virtual MFA device {serial} deleted by {event.get('user_name')}"
                )
            else:  # DeactivateMFADevice
                user_name = request_params.get('userName', 'unknown')
                serial = request_params.get('serialNumber', 'unknown')
                return _create_alert(
                    AlertType.CRITICAL,
                    'MFA Device Deactivated',
                    f"MFA device {serial} deactivated for user '{user_name}' by {event.get('user_name')}"
                )
    
    return None


def check_sso_permission_set_creation(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Check for SSO permission set creation.
    Trigger: CreatePermissionSet (CRITICAL)
    
    Args:
        event: Event to check
        
    Returns:
        Alert dict if suspicious, None otherwise
    """
    if event.get('event_name') == 'CreatePermissionSet':
        request_params = _parse_request_parameters(event)
        if request_params:
            permission_set_name = request_params.get('name', 'unknown')
            instance_arn = request_params.get('instanceArn', 'unknown')
            session_duration = request_params.get('sessionDuration', 'unknown')
            
            return _create_alert(
                AlertType.CRITICAL,
                'SSO Permission Set Created',
                f"New SSO permission set '{permission_set_name}' created by {event.get('user_name')} in instance {instance_arn[-10:]} with session duration {session_duration}"
            )
    
    return None


def check_sso_permission_set_update(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Check for SSO permission set updates.
    Trigger: UpdatePermissionSet (CRITICAL)
    
    Args:
        event: Event to check
        
    Returns:
        Alert dict if suspicious, None otherwise
    """
    if event.get('event_name') == 'UpdatePermissionSet':
        request_params = _parse_request_parameters(event)
        if request_params:
            permission_set_arn = request_params.get('permissionSetArn', 'unknown')
            description = request_params.get('description', '')
            session_duration = request_params.get('sessionDuration', '')
            
            # Extract permission set ID from ARN
            permission_set_id = permission_set_arn.split('/')[-1] if '/' in permission_set_arn else permission_set_arn
            
            return _create_alert(
                AlertType.CRITICAL,
                'SSO Permission Set Updated',
                f"SSO permission set {permission_set_id} updated by {event.get('user_name')} - Description: '{description}', Session Duration: {session_duration}"
            )
    
    return None


def check_sso_admin_policy_attachment(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Check for admin policy attachments to SSO permission sets.
    Trigger: AttachManagedPolicyToPermissionSet with admin policies (CRITICAL)
    
    Args:
        event: Event to check
        
    Returns:
        Alert dict if suspicious, None otherwise
    """
    if event.get('event_name') == 'AttachManagedPolicyToPermissionSet':
        request_params = _parse_request_parameters(event)
        if request_params:
            managed_policy_arn = request_params.get('managedPolicyArn', '')
            permission_set_arn = request_params.get('permissionSetArn', 'unknown')
            
            # Extract permission set ID from ARN
            permission_set_id = permission_set_arn.split('/')[-1] if '/' in permission_set_arn else permission_set_arn
            
            # Check for admin policies
            for admin_policy in ADMIN_POLICY_ARNS:
                if admin_policy in managed_policy_arn:
                    return _create_alert(
                        AlertType.CRITICAL,
                        'Admin Policy Attached to SSO Permission Set',
                        f"Admin policy {admin_policy} attached to SSO permission set {permission_set_id} by {event.get('user_name')}"
                    )
    
    return None


def check_sso_account_assignment(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Check for SSO account assignments.
    Trigger: CreateAccountAssignment (CRITICAL)
    
    Args:
        event: Event to check
        
    Returns:
        Alert dict if suspicious, None otherwise
    """
    if event.get('event_name') == 'CreateAccountAssignment':
        request_params = _parse_request_parameters(event)
        if request_params:
            target_id = request_params.get('targetId', 'unknown')
            target_type = request_params.get('targetType', 'unknown')
            principal_id = request_params.get('principalId', 'unknown')
            principal_type = request_params.get('principalType', 'unknown')
            permission_set_arn = request_params.get('permissionSetArn', 'unknown')
            
            # Extract permission set ID from ARN
            permission_set_id = permission_set_arn.split('/')[-1] if '/' in permission_set_arn else permission_set_arn
            
            return _create_alert(
                AlertType.CRITICAL,
                'SSO Account Assignment Created',
                f"SSO account assignment created by {event.get('user_name')} - {principal_type} {principal_id} granted permission set {permission_set_id} on {target_type} {target_id}"
            )
    
    return None


def check_sso_app_creation(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Check for SSO managed application instance creation.
    Trigger: CreateManagedApplicationInstance (HIGH)
    
    Args:
        event: Event to check
        
    Returns:
        Alert dict if suspicious, None otherwise
    """
    if event.get('event_name') == 'CreateManagedApplicationInstance':
        request_params = _parse_request_parameters(event)
        if request_params:
            display_name = request_params.get('displayName', 'unknown')
            if display_name == 'HIDDEN_DUE_TO_SECURITY_REASONS':
                display_name = 'unknown'
            template_id = request_params.get('templateId', 'unknown')
            start_url = request_params.get('startUrl', 'unknown')
            
            return _create_alert(
                AlertType.HIGH,
                'SSO Application Instance Created',
                f"New SSO application instance '{display_name}' created by {event.get('user_name')} - Template: {template_id}, URL: {start_url}"
            )
    
    return None


def check_sso_app_deletion(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Check for SSO managed application instance deletion.
    Trigger: DeleteManagedApplicationInstance (HIGH)
    
    Args:
        event: Event to check
        
    Returns:
        Alert dict if suspicious, None otherwise
    """
    if event.get('event_name') == 'DeleteManagedApplicationInstance':
        request_params = _parse_request_parameters(event)
        if request_params:
            client_id = request_params.get('clientId', 'unknown')
            
            return _create_alert(
                AlertType.HIGH,
                'SSO Application Instance Deleted',
                f"SSO application instance (client ID: {client_id}) deleted by {event.get('user_name')}"
            )
    
    return None


def has_alert_been_sent(event_id: str, alert_type: str) -> bool:
    """
    Check if an alert has already been sent for this event and alert type.
    
    Args:
        event_id: CloudTrail event ID
        alert_type: Type of alert (CRITICAL, HIGH, WARNING)
        
    Returns:
        bool: True if alert has already been sent
    """
    if not alerts_table:
        logger.warning("Alerts table not available, cannot check deduplication")
        return False
    
    try:
        response = alerts_table.get_item(
            Key={
                'event_id': event_id,
                'alert_type': alert_type
            }
        )
        
        # If item exists, alert has already been sent
        if 'Item' in response:
            logger.info(f"Alert already sent for event {event_id} type {alert_type}")
            return True
            
        return False
        
    except ClientError as e:
        logger.error(f"Error checking alert deduplication: {e}")
        # In case of error, assume alert hasn't been sent to avoid missing critical alerts
        return False


def record_sent_alert(event_id: str, alert_type: str, alert_title: str, message_id: str) -> bool:
    """
    Record that an alert has been sent for this event.
    
    Args:
        event_id: CloudTrail event ID
        alert_type: Type of alert (CRITICAL, HIGH, WARNING)
        alert_title: Title of the alert
        message_id: SNS message ID
        
    Returns:
        bool: True if recorded successfully
    """
    if not alerts_table:
        logger.warning("Alerts table not available, cannot record sent alert")
        return False
    
    try:
        # Calculate TTL (30 days from now to keep alerts history but not forever)
        ttl = int((datetime.now(timezone.utc) + timedelta(days=30)).timestamp())
        
        alerts_table.put_item(
            Item={
                'event_id': event_id,
                'alert_type': alert_type,
                'alert_title': alert_title,
                'message_id': message_id,
                'sent_timestamp': datetime.now(timezone.utc).isoformat(),
                'ttl': ttl
            }
        )
        
        logger.info(f"Recorded sent alert for event {event_id} type {alert_type}")
        return True
        
    except ClientError as e:
        logger.error(f"Error recording sent alert: {e}")
        return False


def send_alert(alert: Dict[str, Any], event: Dict[str, Any]) -> bool:
    """
    Send alert via SNS.
    
    Args:
        alert: Alert information
        event: Original event that triggered the alert
        
    Returns:
        bool: True if sent successfully
    """
    if not sns_client:
        logger.warning("SNS client not initialized, skipping alert")
        return False
    
    try:
        # Build detailed message
        message = f"""
IAM Activity Alert: {alert['title']}

Severity: {alert['type']}
Time: {event.get('event_time')}
Region: {event.get('aws_region')}

{alert['message']}

Event Details:
- Event Name: {event.get('event_name')}
- User: {event.get('user_name')}
- Source IP: {event.get('source_ip')}
- Event ID: {event.get('event_id')}

Action Required: Review this activity immediately in CloudTrail.
"""
        
        # Send SNS notification
        response = sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"[{alert['type']}] IAM Alert: {alert['title']}",
            Message=message,
            MessageAttributes={
                'severity': {
                    'DataType': 'String',
                    'StringValue': alert['type']
                },
                'event_name': {
                    'DataType': 'String',
                    'StringValue': event.get('event_name', 'unknown')
                }
            }
        )
        
        message_id = response['MessageId']
        logger.info(f"Alert sent successfully: {message_id}")
        
        # Record that this alert has been sent
        record_sent_alert(
            event_id=event.get('event_id'),
            alert_type=alert['type'],
            alert_title=alert['title'],
            message_id=message_id
        )
        
        return True
        
    except ClientError as e:
        logger.error(f"Failed to send SNS alert: {e}")
        return False


def check_event_for_alerts(event: Dict[str, Any], dynamodb_table: str) -> None:
    """
    Check a single event for security alerts.
    
    Args:
        event: Transformed event from handler
        dynamodb_table: DynamoDB table name for queries
    """
    if not should_check_alerts(event):
        return
    
    # Get event ID for deduplication
    event_id = event.get('event_id')
    if not event_id:
        logger.warning("Event has no event_id, cannot perform alert deduplication")
        return
    
    # Check each alert type with deduplication
    alerts_to_check = [
        ('root_activity', check_root_activity),
        ('user_creation', check_user_creation),
        ('admin_policy', check_admin_policy_attachment),
        ('dangerous_inline_policy', check_dangerous_inline_policy),
        ('access_key_creation', check_access_key_creation),
        ('role_trust_policy', check_role_trust_policy),
        ('access_key_update', check_access_key_update),
        ('mfa_deletion', check_mfa_deletion),
        ('sso_permission_set_creation', check_sso_permission_set_creation),
        ('sso_permission_set_update', check_sso_permission_set_update),
        ('sso_admin_policy_attachment', check_sso_admin_policy_attachment),
        ('sso_account_assignment', check_sso_account_assignment),
        ('sso_app_creation', check_sso_app_creation),
        ('sso_app_deletion', check_sso_app_deletion)
    ]
    
    alerts_to_send = []
    
    for alert_category, check_function in alerts_to_check:
        alert = check_function(event)
        if alert:
            # Check if this specific alert type has already been sent for this event
            if not has_alert_been_sent(event_id, alert['type']):
                alerts_to_send.append(alert)
            else:
                logger.info(f"Skipping duplicate {alert['type']} alert for event {event_id}")
    
    # Send ALL alerts for this event
    if alerts_to_send:
        logger.info(f"Event {event_id} triggered {len(alerts_to_send)} alerts")
        
        # Send each alert
        for alert in alerts_to_send:
            if send_alert(alert, event):
                logger.info(f"Alert sent for event {event_id}: {alert['title']}")
            else:
                logger.error(f"Failed to send alert for event {event_id}: {alert['title']}")