from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from datetime import datetime
from app.models import User, Application, ActivityLog
from app.schemas.user_schema import (
    UserCreateSchema,
    UserUpdateSchema,
    UserQuerySchema
)
from app.utils.validation import validate_json_body, validate_query_params

users_bp = Blueprint('users', __name__, url_prefix='/api/users')


def require_admin():
    """Decorator to require admin or superadmin role"""
    claims = get_jwt()
    role = claims.get('role', 'user')
    if role not in ['admin', 'superadmin']:
        return jsonify({
            'error': {
                'code': 'FORBIDDEN',
                'message': 'Admin access required'
            }
        }), 403
    return None


def _paginate_firestore(query_results, page, per_page):
    """Helper function to paginate Firestore results"""
    total = len(query_results)
    start = (page - 1) * per_page
    end = start + per_page
    items = query_results[start:end]
    pages = (total + per_page - 1) // per_page
    
    return {
        'items': items,
        'total': total,
        'pages': pages,
        'has_next': end < total,
        'has_prev': page > 1
    }


@users_bp.route('', methods=['GET'])
@jwt_required()
@validate_query_params(UserQuerySchema)
def get_users(validated_data: UserQuerySchema):
    """Get all users with pagination and filtering"""
    error = require_admin()
    if error:
        return error

    # Get all users (Firestore doesn't support complex queries easily)
    all_users = User.get_all()
    
    # Apply filters
    filtered_users = all_users
    
    # Search filter
    if validated_data.search:
        search_term = validated_data.search.lower()
        filtered_users = [
            u for u in filtered_users
            if (hasattr(u, 'email') and search_term in u.email.lower()) or
               (hasattr(u, 'first_name') and u.first_name and search_term in u.first_name.lower()) or
               (hasattr(u, 'last_name') and u.last_name and search_term in u.last_name.lower())
        ]
    
    # Role filter
    if validated_data.role:
        filtered_users = [u for u in filtered_users if hasattr(u, 'role') and u.role == validated_data.role]
    
    # Status filter
    if validated_data.status:
        filtered_users = [u for u in filtered_users if hasattr(u, 'status') and u.status == validated_data.status]
    
    # Sorting
    sort_field = validated_data.sort
    reverse = validated_data.order == 'desc'
    
    def get_sort_value(user):
        if hasattr(user, sort_field):
            value = getattr(user, sort_field)
            if isinstance(value, datetime):
                return value.timestamp() if value else 0
            return value if value else ''
        return ''
    
    filtered_users.sort(key=get_sort_value, reverse=reverse)
    
    # Pagination
    pagination = _paginate_firestore(filtered_users, validated_data.page, validated_data.per_page)

    return jsonify({
        'users': [user.to_dict() for user in pagination['items']],
        'pagination': {
            'page': validated_data.page,
            'per_page': validated_data.per_page,
            'total': pagination['total'],
            'pages': pagination['pages'],
            'has_next': pagination['has_next'],
            'has_prev': pagination['has_prev']
        }
    }), 200


@users_bp.route('', methods=['POST'])
@jwt_required()
@validate_json_body(UserCreateSchema)
def create_user(validated_data: UserCreateSchema):
    """Create a new user"""
    error = require_admin()
    if error:
        return error

    # Check if email already exists
    if User.email_exists(validated_data.email):
        return jsonify({
            'error': {
                'code': 'EMAIL_EXISTS',
                'message': 'A user with this email already exists'
            }
        }), 409

    # Create user
    user = User(
        email=validated_data.email,
        role=validated_data.role,
        status=validated_data.status,
        first_name=validated_data.first_name,
        last_name=validated_data.last_name
    )
    user.set_password(validated_data.password)

    # Assign applications
    if validated_data.application_ids:
        user.assigned_application_ids = validated_data.application_ids

    user.save()

    # Log activity
    current_user_id = get_jwt_identity()
    activity = ActivityLog(
        event_type='user_created',
        user_id=current_user_id,
        description=f'Created user: {user.email}',
        ip_address=request.remote_addr
    )
    activity.save()

    return jsonify({
        'message': 'User created successfully',
        'user': user.to_dict()
    }), 201


@users_bp.route('/<user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    """Get a specific user by ID"""
    error = require_admin()
    if error:
        return error

    user = User.get_by_id(user_id)
    if not user:
        return jsonify({
            'error': {
                'code': 'USER_NOT_FOUND',
                'message': f'User with id {user_id} not found'
            }
        }), 404

    return jsonify(user.to_dict()), 200


@users_bp.route('/<user_id>', methods=['PUT'])
@jwt_required()
@validate_json_body(UserUpdateSchema)
def update_user(user_id, validated_data: UserUpdateSchema):
    """Update a user"""
    error = require_admin()
    if error:
        return error

    user = User.get_by_id(user_id)
    if not user:
        return jsonify({
            'error': {
                'code': 'USER_NOT_FOUND',
                'message': f'User with id {user_id} not found'
            }
        }), 404

    # Update fields (only if provided)
    if validated_data.email:
        # Check if new email already exists
        if User.email_exists(validated_data.email, exclude_id=user_id):
            return jsonify({
                'error': {
                    'code': 'EMAIL_EXISTS',
                    'message': 'A user with this email already exists'
                }
            }), 409
        user.email = validated_data.email

    if validated_data.password:
        user.set_password(validated_data.password)

    if validated_data.role:
        user.role = validated_data.role

    if validated_data.status:
        user.status = validated_data.status

    if validated_data.first_name is not None:
        user.first_name = validated_data.first_name

    if validated_data.last_name is not None:
        user.last_name = validated_data.last_name

    # Update applications
    if validated_data.application_ids is not None:
        user.assigned_application_ids = validated_data.application_ids

    user.save()

    # Log activity
    current_user_id = get_jwt_identity()
    activity = ActivityLog(
        event_type='user_updated',
        user_id=current_user_id,
        description=f'Updated user: {user.email}',
        ip_address=request.remote_addr
    )
    activity.save()

    return jsonify({
        'message': 'User updated successfully',
        'user': user.to_dict()
    }), 200


@users_bp.route('/<user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    """Delete a user"""
    error = require_admin()
    if error:
        return error

    user = User.get_by_id(user_id)
    if not user:
        return jsonify({
            'error': {
                'code': 'USER_NOT_FOUND',
                'message': f'User with id {user_id} not found'
            }
        }), 404

    # Prevent deleting yourself
    current_user_id = get_jwt_identity()
    if user_id == current_user_id:
        return jsonify({
            'error': {
                'code': 'CANNOT_DELETE_SELF',
                'message': 'You cannot delete your own account'
            }
        }), 400

    # Handle activity logs - set user_id to None
    from app.db import get_db
    db = get_db()
    activity_logs = db.collection('activity_logs').where('user_id', '==', user_id).stream()
    for doc in activity_logs:
        doc.reference.update({'user_id': None})

    email = user.email
    user.delete()

    # Log activity
    activity = ActivityLog(
        event_type='user_deleted',
        user_id=current_user_id,
        description=f'Deleted user: {email}',
        ip_address=request.remote_addr
    )
    activity.save()

    return jsonify({
        'message': 'User deleted successfully'
    }), 200


@users_bp.route('/roles', methods=['GET'])
@jwt_required()
def get_roles():
    """Get all available user roles"""
    error = require_admin()
    if error:
        return error
    
    return jsonify({
        'roles': [
            {'value': 'user', 'label': 'User'},
            {'value': 'admin', 'label': 'Admin'},
            {'value': 'superadmin', 'label': 'Super Admin'}
        ]
    }), 200
