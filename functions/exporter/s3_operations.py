"""
S3 Operations Module

Handles S3 bucket operations for analytics data storage including
path generation, bucket validation, and lifecycle management.
"""

import logging
from datetime import datetime
from typing import Dict, Any, Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# S3 client
s3_client = boto3.client('s3')


def validate_s3_bucket(bucket_name: str) -> bool:
    """
    Validate that S3 bucket exists and is accessible.
    
    Args:
        bucket_name: Name of the S3 bucket
        
    Returns:
        bool: True if bucket is valid and accessible
    """
    try:
        s3_client.head_bucket(Bucket=bucket_name)
        logger.info(f"S3 bucket {bucket_name} is accessible")
        return True
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == '404':
            logger.error(f"S3 bucket {bucket_name} does not exist")
        elif error_code == '403':
            logger.error(f"Access denied to S3 bucket {bucket_name}")
        else:
            logger.error(f"Error accessing S3 bucket {bucket_name}: {e}")
        return False


def create_s3_path(bucket: str, date: str, group_key: str) -> str:
    """
    Create optimized S3 path for analytics data.
    
    Args:
        bucket: S3 bucket name
        date: Date in YYYY-MM-DD format
        group_key: Partition group key (e.g., 'source=iam_region=us-east-1')
        
    Returns:
        str: Complete S3 path
    """
    # Parse date components and match Athena partition projection format (no leading zeros)
    date_parts = date.split('-')
    year = date_parts[0]
    month = str(int(date_parts[1]))  # Remove leading zeros to match projection.month.range='1,12'
    day = str(int(date_parts[2]))    # Remove leading zeros to match projection.day.range='1,31'
    
    # Build partitioned path
    base_path = f"s3://{bucket}/iam-events"
    partition_path = f"year={year}/month={month}/day={day}"
    
    # Add group partitions if specified
    if group_key and group_key != 'all':
        group_partitions = group_key.replace('_', '/')
        partition_path = f"{partition_path}/{group_partitions}"
    
    # Generate filename with timestamp for uniqueness
    timestamp = datetime.utcnow().strftime('%H%M%S')
    filename = f"events_{date}_{timestamp}.parquet"
    
    full_path = f"{base_path}/{partition_path}/{filename}"
    logger.info(f"Generated S3 path: {full_path}")
    
    return full_path


def list_existing_exports(bucket: str, date_prefix: str) -> list:
    """
    List existing exports for a given date prefix.
    
    Args:
        bucket: S3 bucket name
        date_prefix: Date prefix (YYYY-MM-DD or YYYY-MM)
        
    Returns:
        list: List of existing S3 objects
    """
    try:
        prefix = f"iam-events/year={date_prefix[:4]}"
        if len(date_prefix) >= 7:
            prefix += f"/month={date_prefix[5:7]}"
        if len(date_prefix) >= 10:
            prefix += f"/day={date_prefix[8:10]}"
        
        response = s3_client.list_objects_v2(
            Bucket=bucket,
            Prefix=prefix
        )
        
        return response.get('Contents', [])
        
    except ClientError as e:
        logger.error(f"Error listing S3 objects: {e}")
        return []


def get_s3_object_metadata(bucket: str, key: str) -> Optional[Dict[str, Any]]:
    """
    Get metadata for an S3 object.
    
    Args:
        bucket: S3 bucket name
        key: S3 object key
        
    Returns:
        dict: Object metadata or None if error
    """
    try:
        response = s3_client.head_object(Bucket=bucket, Key=key)
        return {
            'size': response['ContentLength'],
            'last_modified': response['LastModified'],
            'metadata': response.get('Metadata', {}),
            'content_type': response.get('ContentType', '')
        }
        
    except ClientError as e:
        logger.error(f"Error getting metadata for s3://{bucket}/{key}: {e}")
        return None


def calculate_storage_costs(bucket: str, prefix: str = 'iam-events/') -> Dict[str, Any]:
    """
    Calculate estimated storage costs for IAM events.
    
    Args:
        bucket: S3 bucket name
        prefix: Prefix to analyze
        
    Returns:
        dict: Storage analysis
    """
    try:
        total_size = 0
        object_count = 0
        storage_classes = {}
        
        paginator = s3_client.get_paginator('list_objects_v2')
        
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get('Contents', []):
                size = obj['Size']
                total_size += size
                object_count += 1
                
                # Get storage class
                storage_class = obj.get('StorageClass', 'STANDARD')
                storage_classes[storage_class] = storage_classes.get(storage_class, 0) + size
        
        # Calculate costs (rough estimates in USD)
        cost_per_gb = {
            'STANDARD': 0.023,
            'STANDARD_IA': 0.0125,
            'GLACIER': 0.004,
            'DEEP_ARCHIVE': 0.00099
        }
        
        total_cost = 0
        for storage_class, size_bytes in storage_classes.items():
            size_gb = size_bytes / (1024**3)
            cost = size_gb * cost_per_gb.get(storage_class, 0.023)
            total_cost += cost
        
        return {
            'total_size_bytes': total_size,
            'total_size_gb': total_size / (1024**3),
            'object_count': object_count,
            'storage_classes': storage_classes,
            'estimated_monthly_cost_usd': total_cost
        }
        
    except ClientError as e:
        logger.error(f"Error calculating storage costs: {e}")
        return {'error': str(e)}
