from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity
)
import jwt
from datetime import datetime
from app.models import User, ActivityLog
from app.schemas.user_schema import LoginSchema
from app.utils.validation import validate_json_body

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


@auth_bp.route('/login', methods=['POST'])
@validate_json_body(LoginSchema)
def login(validated_data: LoginSchema):
    """User login endpoint"""
    # Find user
    user = User.get_by_email(validated_data.email)
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
    user.save()

    # Create tokens (identity must be string)
    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={'role': user.role}
    )
    refresh_token = create_refresh_token(identity=str(user.id))

    # Log activity
    activity = ActivityLog(
        event_type='user_login',
        user_id=user.id,
        description=f'User {user.email} logged in',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
    activity.save()

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
    # Identity comes as string from JWT
    user = User.get_by_id(identity)
    if user:
        access_token = create_access_token(
            identity=str(user.id),
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
    # JWT identity is string
    user = User.get_by_id(user_id)
    if user:
        # Log activity
        activity = ActivityLog(
            event_type='user_logout',
            user_id=user.id,
            description=f'User {user.email} logged out',
            ip_address=request.remote_addr
        )
        activity.save()

    return jsonify({
        'message': 'Logout successful'
    }), 200


@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current authenticated user"""
    user_id = get_jwt_identity()
    # JWT identity is string
    user = User.get_by_id(user_id)
    if not user:
        return jsonify({
            'error': {
                'code': 'USER_NOT_FOUND',
                'message': 'User not found'
            }
        }), 404

    return jsonify(user.to_dict()), 200


@auth_bp.route('/verify', methods=['POST', 'GET'])
def verify_token():
    """Verify JWT token validity"""
    # Get token from Authorization header or request body
    token = None
    
    # Try to get from Authorization header
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
    
    # If not in header, try to get from request body (for POST) or query params (for GET)
    if not token:
        if request.is_json and 'token' in request.json:
            token = request.json.get('token')
        elif 'token' in request.args:
            token = request.args.get('token')
    
    if not token:
        return jsonify({
            'error': {
                'code': 'TOKEN_MISSING',
                'message': 'Token is required. Provide it in Authorization header (Bearer <token>) or in request body/query as "token"'
            }
        }), 400
    
    try:
        # Decode and verify the token using PyJWT
        jwt_secret_key = current_app.config.get('JWT_SECRET_KEY')
        decoded_token = jwt.decode(
            token,
            jwt_secret_key,
            algorithms=['HS256'],
            options={'verify_exp': True}
        )
        
        # Get user information
        user_id = decoded_token.get('sub')
        if user_id:
            user = User.get_by_id(user_id)
            if not user:
                return jsonify({
                    'valid': False,
                    'error': {
                        'code': 'USER_NOT_FOUND',
                        'message': 'User associated with token not found'
                    }
                }), 200
            
            # Check if user is active
            if user.status != 'active':
                return jsonify({
                    'valid': False,
                    'error': {
                        'code': 'ACCOUNT_INACTIVE',
                        'message': 'User account is inactive'
                    }
                }), 200
            
            # Get token claims
            role = decoded_token.get('role', 'user')
            exp = decoded_token.get('exp')
            iat = decoded_token.get('iat')
            token_type = decoded_token.get('type', 'access')
            
            # Calculate expiration time
            expires_at = None
            if exp:
                expires_at = datetime.fromtimestamp(exp).isoformat()
            
            return jsonify({
                'valid': True,
                'token_info': {
                    'user_id': user_id,
                    'role': role,
                    'token_type': token_type,
                    'expires_at': expires_at,
                    'issued_at': datetime.fromtimestamp(iat).isoformat() if iat else None
                },
                'user': user.to_dict()
            }), 200
        else:
            return jsonify({
                'valid': False,
                'error': {
                    'code': 'INVALID_TOKEN',
                    'message': 'Token does not contain user identity'
                }
            }), 200
            
    except jwt.ExpiredSignatureError:
        return jsonify({
            'valid': False,
            'error': {
                'code': 'TOKEN_EXPIRED',
                'message': 'Token has expired'
            }
        }), 200
    except jwt.InvalidTokenError as e:
        return jsonify({
            'valid': False,
            'error': {
                'code': 'INVALID_TOKEN',
                'message': f'Token is invalid: {str(e)}'
            }
        }), 200
    except Exception as e:
        return jsonify({
            'valid': False,
            'error': {
                'code': 'TOKEN_ERROR',
                'message': f'Error verifying token: {str(e)}'
            }
        }), 200
