"""
Redis Cache Management API
Provides endpoints to manage Redis cache for the application
"""
from flask import Blueprint, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity
from app.utils.redis_util import (
    get_redis_stats,
    flush_cache,
    check_redis_connection,
    RedisConnectionError
)
from app.middleware.activity_logger import log_activity

redis_cache_bp = Blueprint('redis_cache', __name__)


def require_superadmin():
    """Check if current user has superadmin role"""
    claims = get_jwt()
    role = claims.get('role', 'user')
    if role != 'superadmin':
        return jsonify({'error': 'Superadmin access required'}), 403
    return None


@redis_cache_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_cache_stats():
    """
    Get current Redis cache statistics.
    
    Returns:
        JSON with Redis statistics including db_size, memory usage, etc.
    """
    # Check permissions
    auth_error = require_superadmin()
    if auth_error:
        return auth_error
    
    try:
        stats = get_redis_stats()
        return jsonify({
            'status': 'success',
            'data': stats
        }), 200
    except Exception as e:
        current_app.logger.error(f"Error getting Redis stats: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to get Redis statistics: {str(e)}'
        }), 500


@redis_cache_bp.route('/connection', methods=['GET'])
@jwt_required()
def check_connection():
    """
    Check Redis connection status.
    
    Returns:
        JSON with connection status
    """
    # Check permissions
    auth_error = require_superadmin()
    if auth_error:
        return auth_error
    
    try:
        result = check_redis_connection()
        status_code = 200 if result.get('connected') else 503
        return jsonify({
            'status': 'success' if result.get('connected') else 'error',
            'data': result
        }), status_code
    except Exception as e:
        current_app.logger.error(f"Error checking Redis connection: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to check Redis connection: {str(e)}'
        }), 500


@redis_cache_bp.route('/flush', methods=['POST'])
@jwt_required()
def flush_redis_cache():
    """
    Flush the entire Redis cache (current database only).
    
    This is a destructive operation that clears all cached data.
    Requires superadmin role.
    
    Returns:
        JSON with flush operation result
    """
    # Check permissions
    auth_error = require_superadmin()
    if auth_error:
        return auth_error
    
    try:
        # Get user info for audit logging
        user_id = get_jwt_identity()
        claims = get_jwt()
        user_email = claims.get('email', 'unknown')
        
        # Get stats before flush for logging
        pre_stats = get_redis_stats()
        keys_before = pre_stats.get('db_size', 0) if pre_stats.get('connected') else 0
        
        # Execute flush
        result = flush_cache()
        
        if result['success']:
            # Log the activity for audit trail
            log_activity(
                event_type='redis_cache_flush',
                description=f"Redis cache flushed by {user_email}. Cleared {result['keys_cleared']} keys."
            )
            
            current_app.logger.info(
                f"Redis cache flushed by user {user_id} ({user_email}). "
                f"Cleared {result['keys_cleared']} keys."
            )
            
            return jsonify({
                'status': 'success',
                'message': result['message'],
                'data': {
                    'keys_cleared': result['keys_cleared'],
                    'keys_after': result.get('keys_after', 0),
                    'timestamp': result['timestamp'],
                    'flushed_by': user_email
                }
            }), 200
        else:
            current_app.logger.error(f"Redis flush failed: {result['message']}")
            return jsonify({
                'status': 'error',
                'message': result['message']
            }), 500
            
    except RedisConnectionError as e:
        current_app.logger.error(f"Redis connection error during flush: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Redis connection error: {str(e)}'
        }), 503
    except Exception as e:
        current_app.logger.error(f"Unexpected error during Redis flush: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to flush Redis cache: {str(e)}'
        }), 500
