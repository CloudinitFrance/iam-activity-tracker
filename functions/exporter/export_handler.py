"""
S3 Export Lambda Handler

Daily export of IAM events from DynamoDB to S3 in Parquet format
for long-term analytics and cost-effective storage.
"""

import json
import logging
import os
from datetime import datetime, timedelta, timezone

from parquet_processor import export_events_to_parquet
from s3_operations import create_s3_path, validate_s3_bucket
from dynamodb_operations import scan_events_by_date_range

# Configure logging
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# Environment variables
EVENTS_TABLE = os.environ.get('EVENTS_TABLE_NAME')
S3_BUCKET = os.environ.get('ANALYTICS_BUCKET_NAME')
EXPORT_DAYS_BACK = int(os.environ.get('EXPORT_DAYS_BACK', '1'))
PARTITION_BY_REGION = os.environ.get('PARTITION_BY_REGION', 'true').lower() == 'true'


def lambda_handler(event, context):
    """
    Main export handler function.
    
    Args:
        event: Lambda event (from EventBridge)
        context: Lambda context object
        
    Returns:
        dict: Response with export summary
    """
    logger.info("Starting IAM events export to S3")
    logger.info(f"Event: {json.dumps(event)}")
    
    start_time = datetime.now(timezone.utc)
    export_summary = {
        'total_events_exported': 0,
        'files_created': [],
        'errors': []
    }
    
    try:
        # Validate S3 bucket exists
        if not validate_s3_bucket(S3_BUCKET):
            raise ValueError(f"S3 bucket {S3_BUCKET} does not exist or is not accessible")
        
        # Determine date range to export
        export_dates = get_export_dates()
        logger.info(f"Exporting events for dates: {export_dates}")
        
        # Process each date
        for export_date in export_dates:
            try:
                date_summary = export_events_for_date(export_date)
                export_summary['total_events_exported'] += date_summary['events_count']
                export_summary['files_created'].extend(date_summary['files_created'])
                logger.info(f"Exported {date_summary['events_count']} events for {export_date}")
                
            except Exception as e:
                error_msg = f"Error exporting date {export_date}: {str(e)}"
                logger.error(error_msg)
                export_summary['errors'].append(error_msg)
        
        # Calculate execution time
        execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        # Build response
        response = {
            'statusCode': 200 if not export_summary['errors'] else 500,
            'body': {
                'message': 'Export completed with errors' if export_summary['errors'] else 'Export completed successfully',
                'execution_time_seconds': execution_time,
                'summary': export_summary
            }
        }
        
        logger.info(f"Export complete. Response: {json.dumps(response)}")
        return response
        
    except Exception as e:
        error_msg = f"Fatal error in export handler: {str(e)}"
        logger.error(error_msg)
        export_summary['errors'].append(error_msg)
        
        return {
            'statusCode': 500,
            'body': {
                'message': 'Export failed',
                'summary': export_summary
            }
        }


def get_export_dates():
    """
    Get list of dates to export based on configuration.
    Only exports dates that have data in DynamoDB but no files in S3.
    
    Returns:
        List of date strings in YYYY-MM-DD format
    """
    try:
        # Get all unique dates from DynamoDB that have events
        from s3_operations import list_existing_exports
        import boto3
        
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(EVENTS_TABLE)
        
        logger.info("Scanning DynamoDB for all event dates")
        dates_in_db = set()
        
        # Scan DynamoDB for all unique event dates
        scan_params = {
            'ProjectionExpression': 'event_date',
            'Select': 'SPECIFIC_ATTRIBUTES'
        }
        
        while True:
            response = table.scan(**scan_params)
            
            for item in response.get('Items', []):
                if 'event_date' in item:
                    dates_in_db.add(item['event_date'])
            
            if 'LastEvaluatedKey' in response:
                scan_params['ExclusiveStartKey'] = response['LastEvaluatedKey']
            else:
                break
        
        logger.info(f"Found {len(dates_in_db)} unique dates in DynamoDB")
        
        # Check which dates are missing from S3
        missing_dates = []
        for date in dates_in_db:
            existing_files = list_existing_exports(S3_BUCKET, date)
            if not existing_files:
                missing_dates.append(date)
                logger.info(f"Date {date} needs export (no S3 files found)")
            else:
                logger.debug(f"Date {date} already exported ({len(existing_files)} files in S3)")
        
        sorted_missing_dates = sorted(missing_dates)
        logger.info(f"Found {len(sorted_missing_dates)} dates that need export: {sorted_missing_dates}")
        
        return sorted_missing_dates
        
    except Exception as e:
        logger.error(f"Error determining export dates: {e}")
        logger.info("Falling back to default behavior (export recent days)")
        
        # Fallback to original logic if something goes wrong
        dates = []
        for i in range(EXPORT_DAYS_BACK):
            date = datetime.now(timezone.utc) - timedelta(days=i + 1)
            dates.append(date.strftime('%Y-%m-%d'))
        
        return dates


def export_events_for_date(export_date):
    """
    Export all events for a specific date.
    
    Args:
        export_date: Date string in YYYY-MM-DD format
        
    Returns:
        dict: Export summary for the date
    """
    logger.info(f"Exporting events for date: {export_date}")
    
    # Query DynamoDB for events on this date
    events = scan_events_by_date_range(EVENTS_TABLE, export_date, export_date)
    
    if not events:
        logger.info(f"No events found for {export_date}")
        return {
            'events_count': 0,
            'files_created': []
        }
    
    logger.info(f"Found {len(events)} events for {export_date}")
    
    # Group events for optimal partitioning
    grouped_events = group_events_for_export(events)
    
    files_created = []
    total_exported = 0
    
    # Export each group as separate Parquet file
    for group_key, group_events in grouped_events.items():
        try:
            s3_path = create_s3_path(
                bucket=S3_BUCKET,
                date=export_date,
                group_key=group_key
            )
            
            success = export_events_to_parquet(
                events=group_events,
                s3_path=s3_path
            )
            
            if success:
                files_created.append(s3_path)
                total_exported += len(group_events)
                logger.info(f"Exported {len(group_events)} events to {s3_path}")
            else:
                logger.error(f"Failed to export group {group_key}")
                
        except Exception as e:
            logger.error(f"Error exporting group {group_key}: {e}")
    
    return {
        'events_count': total_exported,
        'files_created': files_created
    }


def group_events_for_export(events):
    """
    Group events for optimal S3 partitioning and file sizes.
    
    Args:
        events: List of events to group
        
    Returns:
        dict: Grouped events by partition key
    """
    groups = {}
    
    for event in events:
        # Build partition key based on configuration (date partitions handled by s3_operations.py)
        partition_parts = []
        
        # Don't use source as a partition - it should be a column in the data
        
        if PARTITION_BY_REGION:
            region = event.get('aws_region', 'unknown')
            partition_parts.append(f"region={region}")
        
        # Create group key
        group_key = '_'.join(partition_parts) if partition_parts else 'all'
        
        # Add event to group
        if group_key not in groups:
            groups[group_key] = []
        groups[group_key].append(event)
    
    # Log group statistics
    for group_key, group_events in groups.items():
        logger.info(f"Group {group_key}: {len(group_events)} events")
    
    return groups
