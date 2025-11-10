from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from sqlalchemy import or_
from app import db
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


@users_bp.route('', methods=['GET'])
@jwt_required()
@validate_query_params(UserQuerySchema)
def get_users(validated_data: UserQuerySchema):
    """Get all users with pagination and filtering"""
    error = require_admin()
    if error:
        return error

    # Build query
    query = User.query

    # Search filter
    if validated_data.search:
        search_term = f"%{validated_data.search}%"
        query = query.filter(
            or_(
                User.email.ilike(search_term),
                User.first_name.ilike(search_term),
                User.last_name.ilike(search_term)
            )
        )

    # Role filter
    if validated_data.role:
        query = query.filter_by(role=validated_data.role)

    # Status filter
    if validated_data.status:
        query = query.filter_by(status=validated_data.status)

    # Sorting
    sort_column = getattr(User, validated_data.sort, User.created_date)
    if validated_data.order == 'desc':
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    # Pagination
    pagination = query.paginate(
        page=validated_data.page,
        per_page=validated_data.per_page,
        error_out=False
    )

    return jsonify({
        'users': [user.to_dict() for user in pagination.items],
        'pagination': {
            'page': validated_data.page,
            'per_page': validated_data.per_page,
            'total': pagination.total,
            'pages': pagination.pages,
            'has_next': pagination.has_next,
            'has_prev': pagination.has_prev
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
    if User.query.filter_by(email=validated_data.email).first():
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
        applications = Application.query.filter(
            Application.id.in_(validated_data.application_ids)
        ).all()
        user.assigned_applications = applications

    db.session.add(user)
    db.session.commit()

    # Log activity
    current_user_id = get_jwt_identity()
    activity = ActivityLog(
        event_type='user_created',
        user_id=current_user_id,
        description=f'Created user: {user.email}',
        ip_address=request.remote_addr
    )
    db.session.add(activity)
    db.session.commit()

    return jsonify({
        'message': 'User created successfully',
        'user': user.to_dict()
    }), 201


@users_bp.route('/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    """Get a specific user by ID"""
    error = require_admin()
    if error:
        return error

    user = User.query.get(user_id)
    if not user:
        return jsonify({
            'error': {
                'code': 'USER_NOT_FOUND',
                'message': f'User with id {user_id} not found'
            }
        }), 404

    return jsonify(user.to_dict()), 200


@users_bp.route('/<int:user_id>', methods=['PUT'])
@jwt_required()
@validate_json_body(UserUpdateSchema)
def update_user(user_id, validated_data: UserUpdateSchema):
    """Update a user"""
    error = require_admin()
    if error:
        return error

    user = User.query.get(user_id)
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
        existing = User.query.filter(
            User.email == validated_data.email,
            User.id != user_id
        ).first()
        if existing:
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
        applications = Application.query.filter(
            Application.id.in_(validated_data.application_ids)
        ).all()
        user.assigned_applications = applications

    db.session.commit()

    # Log activity
    current_user_id = get_jwt_identity()
    activity = ActivityLog(
        event_type='user_updated',
        user_id=current_user_id,
        description=f'Updated user: {user.email}',
        ip_address=request.remote_addr
    )
    db.session.add(activity)
    db.session.commit()

    return jsonify({
        'message': 'User updated successfully',
        'user': user.to_dict()
    }), 200


@users_bp.route('/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    """Delete a user"""
    error = require_admin()
    if error:
        return error

    user = User.query.get(user_id)
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

    email = user.email
    db.session.delete(user)
    db.session.commit()

    # Log activity
    activity = ActivityLog(
        event_type='user_deleted',
        user_id=current_user_id,
        description=f'Deleted user: {email}',
        ip_address=request.remote_addr
    )
    db.session.add(activity)
    db.session.commit()

    return jsonify({
        'message': 'User deleted successfully'
    }), 200

