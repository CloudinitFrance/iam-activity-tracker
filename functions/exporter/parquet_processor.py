"""
Parquet Processing Module

Handles conversion of DynamoDB events to optimized Parquet format
for efficient storage and analytics in S3/Athena.
"""

import io
import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from decimal import Decimal

import boto3
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# S3 client
s3_client = boto3.client('s3')


def export_events_to_parquet(events: List[Dict[str, Any]], s3_path: str) -> bool:
    """
    Convert events to Parquet format and upload to S3.
    
    Args:
        events: List of events from DynamoDB
        s3_path: S3 path (s3://bucket/key)
        
    Returns:
        bool: True if successful, False otherwise
    """
    if not events:
        logger.warning("No events to export")
        return True
    
    try:
        # Convert events to DataFrame
        df = convert_events_to_dataframe(events)
        
        # Optimize DataFrame for analytics
        df = optimize_dataframe_for_analytics(df)
        
        # Convert to Parquet format
        parquet_buffer = create_parquet_buffer(df)
        
        # Upload to S3
        success = upload_parquet_to_s3(parquet_buffer, s3_path)
        
        if success:
            logger.info(f"Successfully exported {len(events)} events to {s3_path}")
            return True
        else:
            logger.error(f"Failed to upload parquet to {s3_path}")
            return False
            
    except Exception as e:
        logger.error(f"Error exporting events to parquet: {e}")
        return False


def convert_events_to_dataframe(events: List[Dict[str, Any]]) -> pd.DataFrame:
    """
    Convert DynamoDB events to pandas DataFrame.
    
    Args:
        events: List of events from DynamoDB
        
    Returns:
        pandas DataFrame
    """
    # Normalize events for DataFrame conversion
    normalized_events = []
    
    for event in events:
        normalized_event = normalize_event_for_dataframe(event)
        normalized_events.append(normalized_event)
    
    # Create DataFrame
    df = pd.DataFrame(normalized_events)
    
    logger.info(f"Created DataFrame with {len(df)} rows and {len(df.columns)} columns")
    return df


def normalize_event_for_dataframe(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a single event for DataFrame conversion.
    
    Args:
        event: Single event from DynamoDB
        
    Returns:
        Normalized event dictionary
    """
    normalized = {}
    
    # Basic fields
    normalized['event_id'] = event.get('event_id', '')
    normalized['event_date'] = event.get('event_date', '')
    normalized['event_time'] = event.get('event_time', '')
    normalized['event_name'] = event.get('event_name', '')
    normalized['event_source'] = event.get('event_source', '')
    normalized['event_type'] = event.get('event_type', '')
    normalized['aws_region'] = event.get('aws_region', '')
    normalized['user_name'] = event.get('user_name', '')
    normalized['source_ip'] = event.get('source_ip', '')
    normalized['user_agent'] = event.get('user_agent', '')
    normalized['error_code'] = event.get('error_code', '')
    normalized['error_message'] = event.get('error_message', '')
    
    # Keep JSON fields as strings to match Athena table schema
    normalized['request_parameters'] = event.get('request_parameters', '{}')
    normalized['response_elements'] = event.get('response_elements', '{}')
    
    # Extract commonly queried fields from request_parameters JSON string
    try:
        req_params = json.loads(normalized['request_parameters']) if normalized['request_parameters'] else {}
        normalized['role_arn'] = req_params.get('roleArn', '')
        normalized['role_session_name'] = req_params.get('roleSessionName', '')
        normalized['policy_arn'] = req_params.get('policyArn', '')
        normalized['user_name_param'] = req_params.get('userName', '')
        normalized['group_name'] = req_params.get('groupName', '')
    except:
        normalized['role_arn'] = ''
        normalized['role_session_name'] = ''
        normalized['policy_arn'] = ''
        normalized['user_name_param'] = ''
        normalized['group_name'] = ''
    
    # Extract response information from response_elements JSON string
    try:
        resp_elements = json.loads(normalized['response_elements']) if normalized['response_elements'] else {}
        normalized['assumed_role_user'] = json.dumps(resp_elements.get('assumedRoleUser', {}))
        normalized['credentials_expiration'] = resp_elements.get('credentials', {}).get('expiration', '')
    except:
        normalized['assumed_role_user'] = '{}'
        normalized['credentials_expiration'] = ''
    
    return normalized


def optimize_dataframe_for_analytics(df: pd.DataFrame) -> pd.DataFrame:
    """
    Optimize DataFrame for analytics and Parquet storage.
    
    Args:
        df: Input DataFrame
        
    Returns:
        Optimized DataFrame
    """
    df_optimized = df.copy()
    
    try:
        # Keep timestamp columns as strings to match Athena table schema
        # Don't convert to actual datetime types
        
        # Optimize string columns (use categories for repeated values)
        categorical_columns = [
            'event_name', 'event_source', 'aws_region',
            'error_code', 'user_name'
        ]
        
        for col in categorical_columns:
            if col in df_optimized.columns:
                unique_ratio = df_optimized[col].nunique() / len(df_optimized)
                if unique_ratio < 0.5:  # Less than 50% unique values
                    df_optimized[col] = df_optimized[col].astype('category')
        
        # Add simple derived columns that don't require datetime operations
        df_optimized['is_error'] = (df_optimized['error_code'] != '') & (df_optimized['error_code'].notna())
        
        # Don't add time-based derived columns since we're keeping timestamps as strings
        # Don't add partition columns - they're handled by S3 path structure
        
        logger.info("DataFrame optimized for analytics")
        return df_optimized
        
    except Exception as e:
        logger.error(f"Error optimizing DataFrame: {e}")
        return df


def create_parquet_buffer(df: pd.DataFrame) -> io.BytesIO:
    """
    Create Parquet format buffer from DataFrame.
    
    Args:
        df: DataFrame to convert
        
    Returns:
        BytesIO buffer containing Parquet data
    """
    buffer = io.BytesIO()
    
    try:
        # Convert DataFrame to PyArrow Table for better control
        table = pa.Table.from_pandas(df)
        
        # Write to Parquet with optimal settings
        pq.write_table(
            table,
            buffer,
            compression='snappy',  # Good balance of compression and speed
            row_group_size=10000,  # Optimize for typical query patterns
            use_dictionary=True,   # Compress repeated values
            write_statistics=True  # Enable predicate pushdown
        )
        
        buffer.seek(0)
        logger.info(f"Created Parquet buffer with {len(buffer.getvalue())} bytes")
        return buffer
        
    except Exception as e:
        logger.error(f"Error creating Parquet buffer: {e}")
        raise


def upload_parquet_to_s3(buffer: io.BytesIO, s3_path: str) -> bool:
    """
    Upload Parquet buffer to S3.
    
    Args:
        buffer: BytesIO buffer containing Parquet data
        s3_path: S3 path (s3://bucket/key)
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Parse S3 path
        if not s3_path.startswith('s3://'):
            raise ValueError(f"Invalid S3 path: {s3_path}")
        
        path_parts = s3_path[5:].split('/', 1)
        bucket = path_parts[0]
        key = path_parts[1] if len(path_parts) > 1 else ''
        
        # Upload with appropriate metadata
        s3_client.put_object(
            Bucket=bucket,
            Key=key,
            Body=buffer.getvalue(),
            ContentType='application/octet-stream',
            Metadata={
                'format': 'parquet',
                'compression': 'snappy',
                'created_by': 'iam-activity-tracker',
                'created_at': datetime.utcnow().isoformat()
            }
        )
        
        logger.info(f"Successfully uploaded Parquet file to {s3_path}")
        return True
        
    except ClientError as e:
        logger.error(f"S3 error uploading to {s3_path}: {e}")
        return False
    except Exception as e:
        logger.error(f"Error uploading to S3: {e}")
        return False


def parse_json_field(json_str: str) -> Any:
    """
    Parse JSON string field from DynamoDB.
    
    Args:
        json_str: JSON string
        
    Returns:
        Parsed object or original string if parsing fails
    """
    if not json_str or json_str == '{}':
        return {}
    
    try:
        return json.loads(json_str)
    except (json.JSONDecodeError, TypeError):
        return json_str


def convert_decimal_to_float(obj):
    """
    Convert Decimal objects to float for JSON serialization.
    
    Args:
        obj: Object that may contain Decimal values
        
    Returns:
        Object with Decimals converted to float
    """
    if isinstance(obj, Decimal):
        return float(obj)
    elif isinstance(obj, dict):
        return {k: convert_decimal_to_float(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_decimal_to_float(v) for v in obj]
    return obj