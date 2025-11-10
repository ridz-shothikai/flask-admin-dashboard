from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt
)
from datetime import datetime
from app import db
from app.models import User, ActivityLog
from app.schemas.user_schema import LoginSchema
from app.utils.validation import validate_json_body

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


@auth_bp.route('/login', methods=['POST'])
@validate_json_body(LoginSchema)
def login(validated_data: LoginSchema):
    """User login endpoint"""
    # Find user
    user = User.query.filter_by(email=validated_data.email).first()
    if not user or not user.check_password(validated_data.password):
        return jsonify({
            'error': {
                'code': 'INVALID_CREDENTIALS',
                'message': 'Invalid email or password'
            }
        }), 401

    # Check if user is active
    if user.status != 'active':
        return jsonify({
            'error': {
                'code': 'ACCOUNT_INACTIVE',
                'message': 'Your account has been deactivated'
            }
        }), 403

    # Update last login
    user.last_login = datetime.utcnow()
    db.session.commit()

    # Create tokens
    access_token = create_access_token(
        identity=user.id,
        additional_claims={'role': user.role}
    )
    refresh_token = create_refresh_token(identity=user.id)

    # Log activity
    activity = ActivityLog(
        event_type='user_login',
        user_id=user.id,
        description=f'User {user.email} logged in',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
    db.session.add(activity)
    db.session.commit()

    return jsonify({
        'message': 'Login successful',
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': user.to_dict()
    }), 200


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token"""
    identity = get_jwt_identity()
    user = User.query.get(identity)
    if user:
        access_token = create_access_token(
            identity=identity,
            additional_claims={'role': user.role}
        )
    else:
        access_token = create_access_token(identity=identity)
    return jsonify({
        'access_token': access_token
    }), 200


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """User logout endpoint"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if user:
        # Log activity
        activity = ActivityLog(
            event_type='user_logout',
            user_id=user.id,
            description=f'User {user.email} logged out',
            ip_address=request.remote_addr
        )
        db.session.add(activity)
        db.session.commit()

    return jsonify({
        'message': 'Logout successful'
    }), 200


@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current authenticated user"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({
            'error': {
                'code': 'USER_NOT_FOUND',
                'message': 'User not found'
            }
        }), 404

    return jsonify(user.to_dict()), 200

