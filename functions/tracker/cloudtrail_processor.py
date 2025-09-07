"""
CloudTrail Event Processing Module

Handles querying CloudTrail for IAM and STS events across regions.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional

import boto3
from botocore.exceptions import ClientError
from botocore.config import Config

logger = logging.getLogger(__name__)

# Configure boto3 client with retry logic
config = Config(
    retries={
        'max_attempts': 3,
        'mode': 'adaptive'
    },
    max_pool_connections=50
)


def get_active_regions() -> List[str]:
    """
    Get list of all active AWS regions.
    
    Returns:
        List of region names
    """
    ec2 = boto3.client('ec2', region_name='us-east-1', config=config)
    try:
        response = ec2.describe_regions(
            Filters=[
                {
                    'Name': 'opt-in-status',
                    'Values': ['opt-in-not-required', 'opted-in']
                }
            ]
        )
        regions = [region['RegionName'] for region in response['Regions']]
        logger.info(f"Found {len(regions)} active regions")
        return regions
    except ClientError as e:
        logger.error(f"Error getting regions: {e}")
        # Return minimal set if API call fails
        return ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1']


def query_cloudtrail_events(
    region: str,
    event_source: str,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    max_results: int = 1000,
    filter_aws_services: bool = True
) -> List[Dict[str, Any]]:
    """
    Query CloudTrail for events from a specific source.
    
    Args:
        region: AWS region to query
        event_source: Event source (iam.amazonaws.com or sts.amazonaws.com)
        start_time: Start time for query (defaults to 90 days ago)
        end_time: End time for query (defaults to now - 5 minutes)
        max_results: Maximum number of results to return
        filter_aws_services: Whether to filter out AWS service events
        
    Returns:
        List of CloudTrail events
    """
    cloudtrail = boto3.client('cloudtrail', region_name=region, config=config)
    
    # Set default times if not provided
    if not start_time:
        start_time = datetime.now(timezone.utc) - timedelta(days=90)
    if not end_time:
        end_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    
    # Ensure times are timezone-aware
    if start_time.tzinfo is None:
        start_time = start_time.replace(tzinfo=timezone.utc)
    if end_time.tzinfo is None:
        end_time = end_time.replace(tzinfo=timezone.utc)
    
    logger.info(f"Querying CloudTrail in {region} for {event_source} events from {start_time} to {end_time}")
    
    events = []
    next_token = None
    
    try:
        while len(events) < max_results:
            # Build lookup attributes
            lookup_attributes = [
                {
                    'AttributeKey': 'EventSource',
                    'AttributeValue': event_source
                }
            ]
            
            # Query CloudTrail
            params = {
                'LookupAttributes': lookup_attributes,
                'StartTime': start_time,
                'EndTime': end_time,
                'MaxResults': min(50, max_results - len(events))  # CloudTrail max is 50 per request
            }
            
            if next_token:
                params['NextToken'] = next_token
            
            response = cloudtrail.lookup_events(**params)
            
            # Process events
            for event in response.get('Events', []):
                # Parse CloudTrail event
                parsed_event = parse_cloudtrail_event(event, filter_aws_services)
                if parsed_event:
                    events.append(parsed_event)
            
            # Check for more results
            next_token = response.get('NextToken')
            if not next_token:
                break
                
        logger.info(f"Retrieved {len(events)} events from {region}")
        return events
        
    except ClientError as e:
        logger.error(f"Error querying CloudTrail in {region}: {e}")
        if e.response['Error']['Code'] == 'AccessDeniedException':
            logger.warning(f"No access to CloudTrail in {region}, skipping")
            return []
        raise


def parse_cloudtrail_event(event: Dict[str, Any], filter_aws_services: bool = True) -> Optional[Dict[str, Any]]:
    """
    Parse a CloudTrail event into a standardized format.
    
    Args:
        event: Raw CloudTrail event
        filter_aws_services: Whether to filter out AWS service events
        
    Returns:
        Parsed event or None if parsing fails or event should be filtered
    """
    try:
        # CloudTrail events have CloudTrailEvent as a JSON string
        if 'CloudTrailEvent' in event:
            import json
            event_detail = json.loads(event['CloudTrailEvent'])
        else:
            event_detail = event
        
        # Extract user identity information
        user_identity = event_detail.get('userIdentity', {})
        event_name = event_detail.get('eventName')
        request_parameters = event_detail.get('requestParameters', {})
        user_name = extract_user_name(user_identity, event_name, request_parameters)
        
        # Build parsed event
        parsed_event = {
            'EventId': event.get('EventId', event_detail.get('eventID')),
            'EventTime': event.get('EventTime', parse_timestamp(event_detail.get('eventTime'))),
            'EventName': event.get('EventName', event_detail.get('eventName')),
            'EventSource': event_detail.get('eventSource'),
            'UserIdentity': user_identity,
            'userName': user_name,
            'SourceIPAddress': event_detail.get('sourceIPAddress'),
            'UserAgent': event_detail.get('userAgent'),
            'RequestParameters': event_detail.get('requestParameters', {}),
            'ResponseElements': event_detail.get('responseElements', {}),
            'ErrorCode': event_detail.get('errorCode'),
            'ErrorMessage': event_detail.get('errorMessage'),
            'AwsRegion': event_detail.get('awsRegion')
        }
        
        # Filter out AWS service events if enabled
        if filter_aws_services and is_service_linked_role_event(parsed_event):
            logger.debug(f"Filtering out AWS service event: {parsed_event['EventName']} by {user_identity.get('type')}")
            return None
        
        return parsed_event
        
    except Exception as e:
        logger.error(f"Error parsing CloudTrail event: {e}")
        return None


def is_service_linked_role_event(event: Dict[str, Any]) -> bool:
    """
    Check if an event is from an AWS service assuming an AWS service-linked role.
    
    This filters AWS internal service maintenance while preserving:
    - User actions (IAMUser, Root, AssumedRole)
    - Application actions (Lambda, EC2 instances, etc.)
    
    Args:
        event: Parsed CloudTrail event
        
    Returns:
        bool: True if event should be filtered (AWS service-linked role)
    """
    user_identity = event.get('UserIdentity', {})
    user_agent = event.get('UserAgent', '')
    source_ip = event.get('SourceIPAddress', '')
    request_params = event.get('RequestParameters', {})
    
    # Check if sessionIssuer ARN contains the reserved AWS service-linked role path
    # This handles AssumedRole events where service-linked roles are used
    if ('sessionContext' in user_identity and 
        'sessionIssuer' in user_identity['sessionContext'] and
        'arn' in user_identity['sessionContext']['sessionIssuer'] and
        '/aws-service-role/' in user_identity['sessionContext']['sessionIssuer']['arn']):
        return True
    
    # Filter AWSService type events
    # Only filter if:
    # 1. Event is from an AWS service (type = AWSService)
    # 2. AND the source is clearly an AWS internal service
    # 3. AND it's assuming a service-linked role
    
    if user_identity.get('type') == 'AWSService':
        # Check if this is an AWS internal service
        aws_service_indicators = [
            user_agent.endswith('.amazonaws.com') if user_agent else False,
            source_ip.endswith('.amazonaws.com') if source_ip else False,
        ]
        
        # Check if assuming service-linked role
        is_service_linked_role = False
        if isinstance(request_params, dict) and 'roleArn' in request_params:
            role_arn = request_params['roleArn']
            is_service_linked_role = '/aws-service-role/' in role_arn
        
        # Filter only if both conditions are met
        if any(aws_service_indicators) and is_service_linked_role:
            return True
    
    return False


def extract_user_name(user_identity: Dict[str, Any], event_name: str = None, request_parameters: Dict[str, Any] = None) -> str:
    """
    Extract user name from various user identity formats.
    
    Args:
        user_identity: UserIdentity object from CloudTrail
        event_name: Name of the CloudTrail event
        request_parameters: Request parameters from CloudTrail event
        
    Returns:
        User name or identifier
    """
    # For AssumeRole events, extract role name from roleArn
    if event_name == 'AssumeRole' and request_parameters and 'roleArn' in request_parameters:
        role_arn = request_parameters['roleArn']
        if '/role/' in role_arn:
            return role_arn.split('/role/')[-1]
    
    # For ConsoleLogin events, handle Root and IAMUser types specially
    if event_name == 'ConsoleLogin':
        user_type = user_identity.get('type')
        if user_type == 'Root':
            return 'root'
        elif user_type == 'IAMUser' and 'userName' in user_identity:
            return user_identity['userName']
    
    # Try different fields in order of preference
    if 'userName' in user_identity:
        return user_identity['userName']
    elif 'sessionContext' in user_identity:
        session_issuer = user_identity['sessionContext'].get('sessionIssuer', {})
        if 'userName' in session_issuer:
            return session_issuer['userName']
    elif 'arn' in user_identity:
        # Extract user/role name from ARN
        arn = user_identity['arn']
        if '/' in arn:
            return arn.split('/')[-1]
    elif 'principalId' in user_identity:
        return user_identity['principalId']
    
    return 'unknown'


def parse_timestamp(timestamp_str: str) -> datetime:
    """
    Parse various timestamp formats from CloudTrail.
    
    Args:
        timestamp_str: Timestamp string
        
    Returns:
        datetime object
    """
    if isinstance(timestamp_str, datetime):
        return timestamp_str
    
    # Try different timestamp formats
    formats = [
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%dT%H:%M:%S.%fZ',
        '%Y-%m-%d %H:%M:%S'
    ]
    
    for fmt in formats:
        try:
            dt = datetime.strptime(timestamp_str, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    
    # If all formats fail, return current time
    logger.warning(f"Could not parse timestamp: {timestamp_str}")
    return datetime.now(timezone.utc)