"""
IAM Activity Tracker Lambda Handler

Main entry point for processing IAM and STS events from CloudTrail
and storing them in DynamoDB for audit and analysis purposes.
"""

import json
import logging
import os
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
from botocore.exceptions import ClientError

from cloudtrail_processor import query_cloudtrail_events, get_active_regions
from dynamodb_operations import (
    batch_write_events,
    get_checkpoint,
    update_checkpoint,
    initialize_control_item
)
from security_alerts import check_event_for_alerts

# Configure logging
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# Environment variables
EVENTS_TABLE = os.environ.get('EVENTS_TABLE_NAME', 'iam-activity-events')
CONTROL_TABLE = os.environ.get('CONTROL_TABLE_NAME', 'iam-activity-control')
MAX_WORKERS = int(os.environ.get('MAX_WORKERS', '16'))
PROCESS_IAM_EVENTS = os.environ.get('PROCESS_IAM_EVENTS', 'true').lower() == 'true'
PROCESS_STS_EVENTS = os.environ.get('PROCESS_STS_EVENTS', 'true').lower() == 'true'
PROCESS_SIGNIN_EVENTS = os.environ.get('PROCESS_SIGNIN_EVENTS', 'true').lower() == 'true'
PROCESS_SSO_EVENTS = os.environ.get('PROCESS_SSO_EVENTS', 'true').lower() == 'true'
SSO_REGION = os.environ.get('SSO_REGION', 'us-east-1')
FILTER_AWS_SERVICE_EVENTS = os.environ.get('FILTER_AWS_SERVICE_EVENTS', 'true').lower() == 'true'


def lambda_handler(event, context):
    """
    Main Lambda handler function.
    
    Args:
        event: Lambda event (from EventBridge)
        context: Lambda context object
        
    Returns:
        dict: Response with processing summary
    """
    logger.info("Starting IAM Activity Tracker")
    logger.info(f"Event: {json.dumps(event)}")
    
    start_time = datetime.now(timezone.utc)
    total_events_processed = 0
    errors = []
    
    try:
        # Get list of active regions
        regions = get_active_regions()
        logger.info(f"Processing {len(regions)} regions")
        
        # Process regions in parallel
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            
            # Submit IAM events processing (us-east-1 only)
            if PROCESS_IAM_EVENTS:
                future = executor.submit(
                    process_region_events,
                    'us-east-1',
                    'iam.amazonaws.com',
                    'iam-events'
                )
                futures.append(('us-east-1-iam', future))
            
            # Submit Signin events processing (us-east-1 only - global events)
            if PROCESS_SIGNIN_EVENTS:
                future = executor.submit(
                    process_region_events,
                    'us-east-1',
                    'signin.amazonaws.com',
                    'signin-events'
                )
                futures.append(('us-east-1-signin', future))
            
            # Submit STS events processing for all regions
            if PROCESS_STS_EVENTS:
                for region in regions:
                    future = executor.submit(
                        process_region_events,
                        region,
                        'sts.amazonaws.com',
                        f'sts-{region}'
                    )
                    futures.append((f'{region}-sts', future))
            
            # Submit SSO events processing
            if PROCESS_SSO_EVENTS:
                # Always process us-east-1 for global SSO events
                future = executor.submit(
                    process_region_events,
                    'us-east-1',
                    'sso.amazonaws.com',
                    'sso-us-east-1'
                )
                futures.append(('us-east-1-sso', future))
                
                # Process the actual SSO region if it's not us-east-1
                if SSO_REGION != 'us-east-1':
                    future = executor.submit(
                        process_region_events,
                        SSO_REGION,
                        'sso.amazonaws.com',
                        f'sso-{SSO_REGION}'
                    )
                    futures.append((f'{SSO_REGION}-sso', future))
            
            # Collect results
            for name, future in futures:
                try:
                    events_count = future.result(timeout=240)
                    total_events_processed += events_count
                    logger.info(f"Processed {events_count} events from {name}")
                except Exception as e:
                    error_msg = f"Error processing {name}: {str(e)}"
                    logger.error(error_msg)
                    errors.append(error_msg)
    
    except Exception as e:
        error_msg = f"Fatal error in handler: {str(e)}"
        logger.error(error_msg)
        errors.append(error_msg)
    
    # Calculate execution time
    execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
    
    # Build response
    response = {
        'statusCode': 200 if not errors else 500,
        'body': {
            'message': 'Processing completed with errors' if errors else 'Processing completed successfully',
            'total_events_processed': total_events_processed,
            'execution_time_seconds': execution_time,
            'errors': errors
        }
    }
    
    logger.info(f"Processing complete. Response: {json.dumps(response)}")
    return response


def process_region_events(region, event_source, checkpoint_key):
    """
    Process events for a specific region and event source.
    
    Args:
        region: AWS region to process
        event_source: Either 'iam.amazonaws.com', 'sts.amazonaws.com', or 'signin.amazonaws.com'
        checkpoint_key: Key for checkpoint storage
        
    Returns:
        int: Number of events processed
    """
    logger.info(f"Processing {event_source} events in {region}")
    
    try:
        # Initialize control item if needed
        initialize_control_item(CONTROL_TABLE, checkpoint_key)
        
        # Get last checkpoint
        checkpoint = get_checkpoint(CONTROL_TABLE, checkpoint_key)
        logger.info(f"Last checkpoint for {checkpoint_key}: {checkpoint}")
        
        # Query CloudTrail events
        events = query_cloudtrail_events(
            region=region,
            event_source=event_source,
            start_time=checkpoint,
            filter_aws_services=FILTER_AWS_SERVICE_EVENTS
        )
        
        if not events:
            logger.info(f"No new events found for {checkpoint_key}")
            return 0
        
        logger.info(f"Found {len(events)} events for {checkpoint_key}")
        
        # Transform events for DynamoDB
        transformed_events = []
        latest_timestamp = checkpoint
        
        for event in events:
            event_time = event['EventTime']
            if latest_timestamp is None or event_time > latest_timestamp:
                latest_timestamp = event_time
            
            transformed_event = {
                'event_date': event_time.strftime('%Y-%m-%d'),
                'event_id': event['EventId'],
                'event_time': event_time.isoformat(),
                'event_name': event['EventName'],
                'event_source': event_source,
                'event_type': 'iam' if event_source == 'iam.amazonaws.com' else ('sts' if event_source == 'sts.amazonaws.com' else ('signin' if event_source == 'signin.amazonaws.com' else ('sso' if event_source == 'sso.amazonaws.com' else 'other'))),
                'aws_region': event.get('AwsRegion', region),
                'user_name': event.get('userName', 'unknown'),
                'source_ip': event.get('SourceIPAddress', 'unknown'),
                'user_agent': event.get('UserAgent', 'unknown'),
                'request_parameters': json.dumps(event.get('RequestParameters', {})),
                'response_elements': json.dumps(event.get('ResponseElements', {})),
                'error_code': event.get('ErrorCode', ''),
                'error_message': event.get('ErrorMessage', '')
            }
            transformed_events.append(transformed_event)
        
        # Batch write to DynamoDB
        success = batch_write_events(EVENTS_TABLE, transformed_events)
        
        if success:
            # Check each event for security alerts
            try:
                for event in transformed_events:
                    check_event_for_alerts(event, EVENTS_TABLE)
            except Exception as e:
                logger.error(f"Error checking alerts: {e}")
                # Continue processing even if alerts fail
            
            # Update checkpoint
            update_checkpoint(
                CONTROL_TABLE,
                checkpoint_key,
                latest_timestamp,
                len(events)
            )
            logger.info(f"Successfully processed {len(events)} events for {checkpoint_key}")
            return len(events)
        else:
            logger.error(f"Failed to write events for {checkpoint_key}")
            return 0
            
    except Exception as e:
        logger.error(f"Error processing {checkpoint_key}: {str(e)}")
        raise