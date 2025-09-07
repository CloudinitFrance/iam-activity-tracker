"""
Athena Query Utilities

Utilities for executing and managing Athena queries on IAM activity data.
Provides both programmatic access and common query templates.
"""

import logging
import time
from typing import List, Dict, Any, Tuple

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Initialize clients
athena_client = boto3.client('athena')
s3_client = boto3.client('s3')


def execute_athena_query(
    query: str,
    database: str,
    workgroup: str,
    output_location: str,
    timeout_seconds: int = 300
) -> Dict[str, Any]:
    """
    Execute an Athena query and return results.
    
    Args:
        query: SQL query to execute
        database: Athena database name
        workgroup: Athena workgroup name
        output_location: S3 location for query results
        timeout_seconds: Query timeout in seconds
        
    Returns:
        dict: Query results and metadata
    """
    try:
        logger.info(f"DEBUG - About to execute query:")
        logger.info(f"DEBUG - Query: {query}")
        logger.info(f"DEBUG - Database: {database}")
        logger.info(f"DEBUG - Workgroup: {workgroup}")
        logger.info(f"DEBUG - Output location: {output_location}")
        
        # Start query execution
        response = athena_client.start_query_execution(
            QueryString=query,
            QueryExecutionContext={'Database': database},
            ResultConfiguration={'OutputLocation': output_location},
            WorkGroup=workgroup
        )
        
        query_execution_id = response['QueryExecutionId']
        logger.info(f"Started Athena query: {query_execution_id}")
        
        # Wait for query completion
        execution_info = wait_for_query_completion(query_execution_id, timeout_seconds)
        
        if execution_info['status'] == 'SUCCEEDED':
            # Get query results
            results = get_query_results(query_execution_id)
            return {
                'status': 'success',
                'query_execution_id': query_execution_id,
                'execution_time_ms': execution_info.get('execution_time_ms'),
                'data_scanned_mb': execution_info.get('data_scanned_mb', 0),
                'cost_estimate_usd': calculate_query_cost(execution_info.get('data_scanned_mb', 0)),
                'results': results
            }
        else:
            return {
                'status': 'failed',
                'query_execution_id': query_execution_id,
                'error': execution_info.get('error', 'Unknown error')
            }
            
    except ClientError as e:
        logger.error(f"ERROR - Failed to execute query: {e}")
        logger.error(f"ERROR - Query that failed: {query}")
        return {
            'status': 'error',
            'error': str(e)
        }


def wait_for_query_completion(query_execution_id: str, timeout_seconds: int = 300) -> Dict[str, Any]:
    """
    Wait for Athena query to complete.
    
    Args:
        query_execution_id: Athena query execution ID
        timeout_seconds: Maximum time to wait
        
    Returns:
        dict: Query execution information
    """
    start_time = time.time()
    
    while time.time() - start_time < timeout_seconds:
        try:
            response = athena_client.get_query_execution(QueryExecutionId=query_execution_id)
            execution = response['QueryExecution']
            status = execution['Status']['State']
            
            if status in ['SUCCEEDED', 'FAILED', 'CANCELLED']:
                result = {
                    'status': status,
                    'query_execution_id': query_execution_id
                }
                
                # Add execution statistics if available
                if 'Statistics' in execution:
                    stats = execution['Statistics']
                    result['execution_time_ms'] = stats.get('EngineExecutionTimeInMillis', 0)
                    result['data_scanned_mb'] = stats.get('DataScannedInBytes', 0) / (1024 * 1024)
                    result['data_processed_mb'] = stats.get('DataProcessedInBytes', 0) / (1024 * 1024)
                
                # Add error information if query failed
                if status == 'FAILED' and 'StateChangeReason' in execution['Status']:
                    result['error'] = execution['Status']['StateChangeReason']
                
                return result
                
        except ClientError as e:
            logger.error(f"Error checking query status: {e}")
            return {
                'status': 'ERROR',
                'error': str(e)
            }
        
        time.sleep(2)  # Wait 2 seconds before checking again
    
    return {
        'status': 'TIMEOUT',
        'error': f'Query did not complete within {timeout_seconds} seconds'
    }


def get_query_results(query_execution_id: str, max_results: int = 1000) -> List[Dict[str, Any]]:
    """
    Get results from completed Athena query.
    
    Args:
        query_execution_id: Athena query execution ID
        max_results: Maximum number of results to return
        
    Returns:
        list: Query results as list of dictionaries
    """
    try:
        results = []
        next_token = None
        
        while len(results) < max_results:
            params = {
                'QueryExecutionId': query_execution_id,
                'MaxResults': min(1000, max_results - len(results))
            }
            
            if next_token:
                params['NextToken'] = next_token
            
            response = athena_client.get_query_results(**params)
            result_set = response['ResultSet']
            
            # Get column names from metadata
            if 'ColumnInfo' in result_set['ResultSetMetadata']:
                column_names = [col['Name'] for col in result_set['ResultSetMetadata']['ColumnInfo']]
            else:
                column_names = []
            
            # Process rows (skip header row)
            rows = result_set['Rows']
            if results == [] and rows:  # Skip header row for first batch
                rows = rows[1:]
            
            for row in rows:
                if len(results) >= max_results:
                    break
                    
                row_data = {}
                for i, value in enumerate(row['Data']):
                    if i < len(column_names):
                        row_data[column_names[i]] = value.get('VarCharValue', '')
                results.append(row_data)
            
            # Check for more results
            next_token = response.get('NextToken')
            if not next_token:
                break
        
        logger.info(f"Retrieved {len(results)} rows from query {query_execution_id}")
        return results
        
    except ClientError as e:
        logger.error(f"Error getting query results: {e}")
        return []


def calculate_query_cost(data_scanned_mb: float) -> float:
    """
    Calculate estimated cost for Athena query.
    
    Args:
        data_scanned_mb: Amount of data scanned in MB
        
    Returns:
        float: Estimated cost in USD
    """
    # Athena pricing: $5 per TB scanned
    data_scanned_tb = data_scanned_mb / (1024 * 1024)
    cost_per_tb = 5.0
    return data_scanned_tb * cost_per_tb


def create_iam_events_table(
    database: str,
    table_name: str,
    s3_location: str,
    workgroup: str,
    output_location: str
) -> Dict[str, Any]:
    """
    Create Athena table for IAM events data.
    
    Args:
        database: Athena database name
        table_name: Table name to create
        s3_location: S3 location of Parquet files
        workgroup: Athena workgroup
        output_location: S3 location for query results
        
    Returns:
        dict: Table creation result
    """
    create_table_query = f"""CREATE EXTERNAL TABLE IF NOT EXISTS {database}.{table_name} (
        event_date string,
        event_id string,
        event_time string,
        event_name string,
        event_type string,
        user_name string,
        source_ip string,
        user_agent string,
        request_parameters string,
        response_elements string,
        error_code string,
        error_message string
    )
    PARTITIONED BY (
        year int,
        month int,
        day int,
        region string
    )
    STORED AS PARQUET
    LOCATION '{s3_location}'
    TBLPROPERTIES (
        'projection.enabled'='true',
        'projection.year.type'='integer',
        'projection.year.range'='2020,2030',
        'projection.month.type'='integer',
        'projection.month.range'='1,12',
        'projection.day.type'='integer',
        'projection.day.range'='1,31',
        'projection.region.type'='enum',
        'projection.region.values'='us-east-1,us-west-1,us-west-2,eu-west-1,eu-central-1,ap-southeast-1,ap-northeast-1,ca-central-1,ap-south-1,sa-east-1,eu-north-1,ap-northeast-2,ap-northeast-3,ap-southeast-2,eu-west-2,eu-west-3',
        'storage.location.template'='{s3_location}/year=${{year}}/month=${{month}}/day=${{day}}/region=${{region}}/'
    )
    """
    
    return execute_athena_query(
        query=create_table_query,
        database=database,
        workgroup=workgroup,
        output_location=output_location
    )


def repair_table_partitions(
    database: str,
    table_name: str,
    workgroup: str,
    output_location: str
) -> Dict[str, Any]:
    """
    Repair table partitions to discover new data.
    
    Args:
        database: Athena database name
        table_name: Table name
        workgroup: Athena workgroup
        output_location: S3 location for query results
        
    Returns:
        dict: Repair operation result
    """
    repair_query = f"MSCK REPAIR TABLE {database}.{table_name}"
    
    return execute_athena_query(
        query=repair_query,
        database=database,
        workgroup=workgroup,
        output_location=output_location
    )


def get_table_statistics(
    database: str,
    table_name: str,
    workgroup: str,
    output_location: str
) -> Dict[str, Any]:
    """
    Get statistics about the IAM events table.
    
    Args:
        database: Athena database name
        table_name: Table name
        workgroup: Athena workgroup
        output_location: S3 location for query results
        
    Returns:
        dict: Table statistics
    """
    stats_query = f"""
    SELECT 
        COUNT(*) as total_events,
        COUNT(DISTINCT user_name) as unique_users,
        COUNT(DISTINCT event_name) as unique_actions,
        MIN(event_time) as earliest_event,
        MAX(event_time) as latest_event,
        COUNT(CASE WHEN error_code IS NOT NULL AND error_code != '' THEN 1 END) as error_events,
        COUNT(DISTINCT event_date) as days_with_data
    FROM {database}.{table_name}
    """
    
    return execute_athena_query(
        query=stats_query,
        database=database,
        workgroup=workgroup,
        output_location=output_location
    )


def validate_s3_location(s3_location: str) -> bool:
    """
    Validate that S3 location exists and contains data.
    
    Args:
        s3_location: S3 path to validate
        
    Returns:
        bool: True if valid location with data
    """
    try:
        # Parse S3 path
        if not s3_location.startswith('s3://'):
            return False
        
        path_parts = s3_location[5:].split('/', 1)
        bucket = path_parts[0]
        prefix = path_parts[1] if len(path_parts) > 1 else ''
        
        # Check if bucket exists and we can list objects
        response = s3_client.list_objects_v2(
            Bucket=bucket,
            Prefix=prefix,
            MaxKeys=1
        )
        
        # Return True if we found at least one object
        return 'Contents' in response and len(response['Contents']) > 0
        
    except ClientError as e:
        logger.error(f"Error validating S3 location {s3_location}: {e}")
        return False