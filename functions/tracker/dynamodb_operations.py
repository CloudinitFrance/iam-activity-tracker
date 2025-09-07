"""
DynamoDB Operations Module

Handles all DynamoDB operations for storing IAM events and managing checkpoints.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from decimal import Decimal

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Initialize DynamoDB client
dynamodb = boto3.client('dynamodb')
dynamodb_resource = boto3.resource('dynamodb')


def batch_write_events(table_name: str, events: List[Dict[str, Any]]) -> bool:
    """
    Batch write events to DynamoDB.
    
    Args:
        table_name: Name of the DynamoDB table
        events: List of events to write
        
    Returns:
        bool: True if successful, False otherwise
    """
    if not events:
        return True
    
    table = dynamodb_resource.Table(table_name)
    
    # DynamoDB batch write limit is 25 items
    batch_size = 25
    total_written = 0
    
    try:
        for i in range(0, len(events), batch_size):
            batch = events[i:i + batch_size]
            
            with table.batch_writer() as batch_writer:
                for event in batch:
                    # Convert to DynamoDB-safe format
                    safe_event = convert_to_dynamodb_format(event)
                    
                    # Write event using batch writer (no conditions supported)
                    batch_writer.put_item(Item=safe_event)
                    total_written += 1
            
            logger.info(f"Written batch of {len(batch)} events to {table_name}")
        
        logger.info(f"Successfully written {total_written} new events to {table_name}")
        return True
        
    except ClientError as e:
        logger.error(f"Error writing events to DynamoDB: {e}")
        return False


def get_checkpoint(table_name: str, region_key: str) -> Optional[datetime]:
    """
    Get the last processed checkpoint for a region.
    
    Args:
        table_name: Name of the control table
        region_key: Region identifier
        
    Returns:
        datetime: Last processed timestamp or None
    """
    try:
        response = dynamodb.get_item(
            TableName=table_name,
            Key={
                'region': {'S': region_key}
            }
        )
        
        if 'Item' in response:
            timestamp_str = response['Item'].get('last_processed_timestamp', {}).get('S')
            if timestamp_str:
                return datetime.fromisoformat(timestamp_str)
        
        return None
        
    except ClientError as e:
        logger.error(f"Error getting checkpoint for {region_key}: {e}")
        return None


def update_checkpoint(
    table_name: str,
    region_key: str,
    timestamp: datetime,
    events_count: int
) -> bool:
    """
    Update the checkpoint for a region.
    
    Args:
        table_name: Name of the control table
        region_key: Region identifier
        timestamp: Latest processed timestamp
        events_count: Number of events processed
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Get current count
        current_count = 0
        response = dynamodb.get_item(
            TableName=table_name,
            Key={'region': {'S': region_key}},
            ProjectionExpression='events_processed_count'
        )
        if 'Item' in response and 'events_processed_count' in response['Item']:
            current_count = int(response['Item']['events_processed_count']['N'])
        
        # Update checkpoint
        dynamodb.update_item(
            TableName=table_name,
            Key={
                'region': {'S': region_key}
            },
            UpdateExpression="""
                SET last_processed_timestamp = :timestamp,
                    last_execution_time = :exec_time,
                    events_processed_count = :count,
                    processing_status = :status
            """,
            ExpressionAttributeValues={
                ':timestamp': {'S': timestamp.isoformat()},
                ':exec_time': {'S': datetime.now(timezone.utc).isoformat()},
                ':count': {'N': str(current_count + events_count)},
                ':status': {'S': 'active'}
            }
        )
        
        logger.info(f"Updated checkpoint for {region_key}: {timestamp}")
        return True
        
    except ClientError as e:
        logger.error(f"Error updating checkpoint for {region_key}: {e}")
        return False


def initialize_control_item(table_name: str, region_key: str) -> bool:
    """
    Initialize a control item if it doesn't exist.
    
    Args:
        table_name: Name of the control table
        region_key: Region identifier
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Try to create item with conditional check
        # Initialize with a timestamp 90 days ago (CloudTrail's limit)
        initial_timestamp = datetime.now(timezone.utc) - timedelta(days=90)
        
        dynamodb.put_item(
            TableName=table_name,
            Item={
                'region': {'S': region_key},
                'last_processed_timestamp': {'S': initial_timestamp.isoformat()},
                'last_execution_time': {'S': datetime.now(timezone.utc).isoformat()},
                'events_processed_count': {'N': '0'},
                'processing_status': {'S': 'active'},
                'last_error': {'S': ''}
            },
            ConditionExpression='attribute_not_exists(#region)',
            ExpressionAttributeNames={'#region': 'region'}
        )
        logger.info(f"Initialized control item for {region_key}")
        return True
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            # Item already exists, that's fine
            logger.debug(f"Control item for {region_key} already exists")
            return True
        else:
            logger.error(f"Error initializing control item for {region_key}: {e}")
            return False


def convert_to_dynamodb_format(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert Python types to DynamoDB-safe format.
    
    Args:
        item: Dictionary to convert
        
    Returns:
        DynamoDB-safe dictionary
    """
    def convert_value(value):
        if isinstance(value, float):
            return Decimal(str(value))
        elif isinstance(value, datetime):
            return value.isoformat()
        elif isinstance(value, dict):
            return {k: convert_value(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [convert_value(v) for v in value]
        return value
    
    return {k: convert_value(v) for k, v in item.items()}


def query_events_by_user(
    table_name: str,
    user_name: str,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Query events by user name using GSI.
    
    Args:
        table_name: Name of the events table
        user_name: User name to query
        start_date: Start date (YYYY-MM-DD)
        end_date: End date (YYYY-MM-DD)
        limit: Maximum number of results
        
    Returns:
        List of events
    """
    table = dynamodb_resource.Table(table_name)
    
    try:
        # Build query parameters
        query_params = {
            'IndexName': 'user_name-index',
            'KeyConditionExpression': 'user_name = :username',
            'ExpressionAttributeValues': {
                ':username': user_name
            },
            'Limit': limit
        }
        
        # Add date range if provided
        if start_date and end_date:
            query_params['FilterExpression'] = 'event_date BETWEEN :start AND :end'
            query_params['ExpressionAttributeValues'].update({
                ':start': start_date,
                ':end': end_date
            })
        
        response = table.query(**query_params)
        return response.get('Items', [])
        
    except ClientError as e:
        logger.error(f"Error querying events by user {user_name}: {e}")
        return []


def query_events_by_action(
    table_name: str,
    event_name: str,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Query events by action/event name using GSI.
    
    Args:
        table_name: Name of the events table
        event_name: Event name to query
        start_date: Start date (YYYY-MM-DD)
        end_date: End date (YYYY-MM-DD)
        limit: Maximum number of results
        
    Returns:
        List of events
    """
    table = dynamodb_resource.Table(table_name)
    
    try:
        # Build query parameters
        query_params = {
            'IndexName': 'event_name-index',
            'KeyConditionExpression': 'event_name = :eventname',
            'ExpressionAttributeValues': {
                ':eventname': event_name
            },
            'Limit': limit
        }
        
        # Add date range if provided
        if start_date and end_date:
            query_params['FilterExpression'] = 'event_date BETWEEN :start AND :end'
            query_params['ExpressionAttributeValues'].update({
                ':start': start_date,
                ':end': end_date
            })
        
        response = table.query(**query_params)
        return response.get('Items', [])
        
    except ClientError as e:
        logger.error(f"Error querying events by action {event_name}: {e}")
        return []