"""
Redis Utility Module
Provides functions for Redis cache management operations
"""
import redis
from flask import current_app
from datetime import datetime
from typing import Dict, Any, Optional


class RedisConnectionError(Exception):
    """Custom exception for Redis connection errors"""
    pass


def get_redis_client() -> redis.Redis:
    """
    Get a Redis client instance using app configuration.
    
    Returns:
        redis.Redis: Connected Redis client instance
        
    Raises:
        RedisConnectionError: If connection cannot be established
    """
    try:
        client = redis.Redis(
            host=current_app.config.get('REDIS_HOST', 'localhost'),
            port=current_app.config.get('REDIS_PORT', 6379),
            password=current_app.config.get('REDIS_PASSWORD'),
            db=current_app.config.get('REDIS_DB', 0),
            decode_responses=True,
            socket_timeout=5,
            socket_connect_timeout=5
        )
        # Test connection
        client.ping()
        return client
    except redis.ConnectionError as e:
        raise RedisConnectionError(f"Failed to connect to Redis: {str(e)}")
    except redis.AuthenticationError as e:
        raise RedisConnectionError(f"Redis authentication failed: {str(e)}")
    except Exception as e:
        raise RedisConnectionError(f"Redis error: {str(e)}")


def get_redis_stats() -> Dict[str, Any]:
    """
    Get current Redis cache statistics.
    
    Returns:
        dict: Redis statistics including db_size, memory_used, etc.
    """
    try:
        client = get_redis_client()
        info = client.info()
        db_size = client.dbsize()
        
        return {
            'connected': True,
            'db_size': db_size,
            'memory_used': info.get('used_memory_human', 'N/A'),
            'memory_used_bytes': info.get('used_memory', 0),
            'uptime_seconds': info.get('uptime_in_seconds', 0),
            'connected_clients': info.get('connected_clients', 0),
            'redis_version': info.get('redis_version', 'N/A'),
            'host': current_app.config.get('REDIS_HOST', 'localhost'),
            'port': current_app.config.get('REDIS_PORT', 6379),
            'db': current_app.config.get('REDIS_DB', 0)
        }
    except RedisConnectionError as e:
        return {
            'connected': False,
            'error': str(e),
            'host': current_app.config.get('REDIS_HOST', 'localhost'),
            'port': current_app.config.get('REDIS_PORT', 6379),
            'db': current_app.config.get('REDIS_DB', 0)
        }


def flush_cache() -> Dict[str, Any]:
    """
    Flush all keys in the current Redis database.
    
    Uses FLUSHDB to clear only the selected database (not FLUSHALL).
    
    Returns:
        dict: Result of the flush operation including:
            - success: bool
            - message: str
            - keys_cleared: int (number of keys before flush)
            - timestamp: str (ISO format)
    """
    try:
        client = get_redis_client()
        
        # Get count before flush for reporting
        keys_before = client.dbsize()
        
        # Execute FLUSHDB (clears current database only)
        client.flushdb()
        
        # Verify flush succeeded
        keys_after = client.dbsize()
        
        return {
            'success': True,
            'message': f'Redis cache flushed successfully. Cleared {keys_before} keys.',
            'keys_cleared': keys_before,
            'keys_after': keys_after,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
    except RedisConnectionError as e:
        return {
            'success': False,
            'message': str(e),
            'keys_cleared': 0,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
    except Exception as e:
        return {
            'success': False,
            'message': f'Failed to flush Redis cache: {str(e)}',
            'keys_cleared': 0,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }


def check_redis_connection() -> Dict[str, Any]:
    """
    Check if Redis connection is available.
    
    Returns:
        dict: Connection status with details
    """
    try:
        client = get_redis_client()
        client.ping()
        return {
            'connected': True,
            'message': 'Redis connection successful',
            'host': current_app.config.get('REDIS_HOST', 'localhost'),
            'port': current_app.config.get('REDIS_PORT', 6379)
        }
    except RedisConnectionError as e:
        return {
            'connected': False,
            'message': str(e),
            'host': current_app.config.get('REDIS_HOST', 'localhost'),
            'port': current_app.config.get('REDIS_PORT', 6379)
        }
