# app/routes/auth.py

from flask import Blueprint, request, jsonify, current_app, redirect, Response
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity
)
import jwt
from datetime import datetime
import base64
import xml.etree.ElementTree as ET
import re
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
        description=f'User {user.email} logged in via password',
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
    # Identity comes as string from JWT, convert to int for query
    user = User.query.get(int(identity))
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
    # JWT identity is string, convert to int for database query
    user = User.query.get(int(user_id))
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
    # JWT identity is string, convert to int for database query
    user = User.query.get(int(user_id))
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
            user = User.query.get(int(user_id))
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


# ==================== SAML ROUTES ====================

def prepare_flask_request(req):
    """Prepare Flask request for SAML library"""
    return {
        'https': 'on' if req.scheme == 'https' else 'off',
        'http_host': req.host,
        'server_port': req.environ.get('SERVER_PORT'),
        'script_name': req.path,
        'get_data': req.args.copy(),
        'post_data': req.form.copy()
    }


def extract_email_from_saml(saml_response_b64):
    """
    Extract email from base64-encoded SAML response.
    
    Tries multiple methods:
    1. NameID element
    2. Attribute elements (email, mail, emailaddress)
    3. Regex search as fallback
    """
    try:
        # Decode base64
        saml_xml = base64.b64decode(saml_response_b64)
        root = ET.fromstring(saml_xml)
        
        # Define namespaces
        namespaces = {
            'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion',
            'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        }
        
        # Method 1: Try NameID
        for ns_prefix in ['saml2', 'saml', '']:
            if ns_prefix:
                path = f'.//{ns_prefix}:NameID'
                nameid = root.find(path, namespaces)
            else:
                nameid = root.find('.//NameID')
            
            if nameid is not None and nameid.text:
                current_app.logger.info(f"Email found in NameID: {nameid.text}")
                return nameid.text
        
        # Method 2: Try attributes
        for ns_prefix in ['saml2', 'saml', '']:
            if ns_prefix:
                attrs = root.findall(f'.//{ns_prefix}:Attribute', namespaces)
            else:
                attrs = root.findall('.//Attribute')
            
            for attr in attrs:
                attr_name = attr.get('Name', '').lower()
                if any(keyword in attr_name for keyword in ['email', 'mail', 'emailaddress']):
                    # Try to find value
                    for value_pattern in ['.//saml2:AttributeValue', './/saml:AttributeValue', './/*AttributeValue*']:
                        value_elem = attr.find(value_pattern, namespaces if 'saml' in value_pattern else {})
                        if value_elem is not None and value_elem.text:
                            current_app.logger.info(f"Email found in attribute {attr_name}: {value_elem.text}")
                            return value_elem.text
        
        # Method 3: Regex fallback
        xml_str = saml_xml.decode('utf-8', errors='ignore')
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        matches = re.findall(email_pattern, xml_str)
        if matches:
            current_app.logger.info(f"Email found via regex: {matches[0]}")
            return matches[0]
        
        current_app.logger.error("No email found in SAML response")
        return None
        
    except Exception as e:
        current_app.logger.error(f"Error extracting email from SAML: {e}", exc_info=True)
        return None


@auth_bp.route('/saml/login', methods=['GET'])
def saml_login():
    """
    Initiate SAML SSO login.
    Redirects user to Identity Provider (IdP) for authentication.
    """
    try:
        # Check if SAML is enabled
        if not current_app.config.get('SAML_ENABLED', False):
            return jsonify({
                'error': {
                    'code': 'SAML_DISABLED',
                    'message': 'SAML authentication is not enabled'
                }
            }), 400
        
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
        from config.saml_settings import get_saml_settings
        
        saml_settings = get_saml_settings()
        auth = OneLogin_Saml2_Auth(
            prepare_flask_request(request),
            old_settings=saml_settings
        )
        
        # Redirect to IdP
        sso_url = auth.login()
        current_app.logger.info(f"Redirecting to IdP: {sso_url}")
        
        return redirect(sso_url)
        
    except Exception as e:
        current_app.logger.error(f"SAML login error: {e}", exc_info=True)
        return jsonify({
            'error': {
                'code': 'SAML_LOGIN_ERROR',
                'message': f'Failed to initiate SAML login: {str(e)}'
            }
        }), 500


@auth_bp.route('/saml/acs', methods=['POST'])
def saml_acs():
    """
    SAML Assertion Consumer Service (ACS).
    Handles the SAML response from the Identity Provider.
    """
    try:
        current_app.logger.info("SAML ACS endpoint called")
        
        # Check if SAML response exists
        if 'SAMLResponse' not in request.form:
            current_app.logger.error("No SAMLResponse in form data")
            frontend_url = current_app.config.get('FRONTEND_URL')
            return redirect(f"{frontend_url}/auth/error?message=No SAML response received")
        
        # Validate SAML response first (CRITICAL SECURITY STEP)
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
        from config.saml_settings import get_saml_settings
        
        saml_settings = get_saml_settings()
        auth = OneLogin_Saml2_Auth(
            prepare_flask_request(request),
            old_settings=saml_settings
        )
        
        # Process and validate the SAML response
        auth.process_response()
        errors = auth.get_errors()
        
        if errors:
            current_app.logger.error(f"SAML validation errors: {errors}")
            frontend_url = current_app.config.get('FRONTEND_URL')
            return redirect(f"{frontend_url}/auth/error?message=SAML validation failed")
        
        # Check if user is authenticated
        if not auth.is_authenticated():
            current_app.logger.error("SAML authentication failed - user not authenticated")
            frontend_url = current_app.config.get('FRONTEND_URL')
            return redirect(f"{frontend_url}/auth/error?message=Authentication failed")
        
        # Get user attributes from validated SAML response
        saml_attributes = auth.get_attributes()
        nameid = auth.get_nameid()
        
        # Extract email - prefer NameID, then attributes, then fallback to extraction
        email = None
        if nameid:
            email = nameid
            current_app.logger.info(f"Email from NameID: {email}")
        elif saml_attributes:
            # Try to get email from attributes
            for attr_name in ['email', 'mail', 'Email', 'EmailAddress', 'emailaddress']:
                if attr_name in saml_attributes and saml_attributes[attr_name]:
                    email = saml_attributes[attr_name][0] if isinstance(saml_attributes[attr_name], list) else saml_attributes[attr_name]
                    current_app.logger.info(f"Email from attribute {attr_name}: {email}")
                    break
        
        # Fallback: extract from raw SAML response if not found in validated attributes
        if not email:
            email = extract_email_from_saml(request.form['SAMLResponse'])
        
        if not email:
            current_app.logger.error("Could not extract email from SAML response")
            frontend_url = current_app.config.get('FRONTEND_URL')
            return redirect(f"{frontend_url}/auth/error?message=Email not found in SAML response")
        
        current_app.logger.info(f"Email extracted from SAML: {email}")
        
        # Find user in database
        user = User.query.filter_by(email=email).first()
        
        # Auto-provision user if they don't exist (common SSO pattern)
        if not user:
            current_app.logger.info(f"User not found, auto-provisioning SSO user: {email}")
            
            # Extract additional attributes from SAML if available
            first_name = None
            last_name = None
            
            # Try to get name from SAML attributes
            if saml_attributes:
                # Common attribute names for first/last name
                if 'firstName' in saml_attributes and saml_attributes['firstName']:
                    first_name = saml_attributes['firstName'][0] if isinstance(saml_attributes['firstName'], list) else saml_attributes['firstName']
                elif 'givenName' in saml_attributes and saml_attributes['givenName']:
                    first_name = saml_attributes['givenName'][0] if isinstance(saml_attributes['givenName'], list) else saml_attributes['givenName']
                elif 'first_name' in saml_attributes and saml_attributes['first_name']:
                    first_name = saml_attributes['first_name'][0] if isinstance(saml_attributes['first_name'], list) else saml_attributes['first_name']
                
                if 'lastName' in saml_attributes and saml_attributes['lastName']:
                    last_name = saml_attributes['lastName'][0] if isinstance(saml_attributes['lastName'], list) else saml_attributes['lastName']
                elif 'surname' in saml_attributes and saml_attributes['surname']:
                    last_name = saml_attributes['surname'][0] if isinstance(saml_attributes['surname'], list) else saml_attributes['surname']
                elif 'last_name' in saml_attributes and saml_attributes['last_name']:
                    last_name = saml_attributes['last_name'][0] if isinstance(saml_attributes['last_name'], list) else saml_attributes['last_name']
            
            # Fallback: try to extract from email if name not in attributes
            if not first_name and not last_name:
                email_parts = email.split('@')[0].split('.')
                if len(email_parts) >= 2:
                    first_name = email_parts[0].title()
                    last_name = email_parts[1].title()
                elif len(email_parts) == 1:
                    first_name = email_parts[0].title()
            
            # Get default role from config or use 'user'
            default_role = current_app.config.get('SAML_DEFAULT_ROLE', 'user')
            
            # Create new SSO user
            user = User(
                email=email,
                role=default_role,
                status='active',
                first_name=first_name,
                last_name=last_name,
                is_sso_user=True
            )
            
            db.session.add(user)
            db.session.commit()
            
            current_app.logger.info(f"Auto-provisioned new SSO user: {email} with role: {default_role}")
            
            # Log user creation activity
            activity = ActivityLog(
                event_type='user_created',
                user_id=user.id,
                description=f'User {user.email} auto-created via SAML SSO',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            db.session.add(activity)
            db.session.commit()
        
        # Check if user is active
        if user.status != 'active':
            current_app.logger.warning(f"Inactive user attempted login: {email}")
            frontend_url = current_app.config.get('FRONTEND_URL')
            return redirect(f"{frontend_url}/auth/error?message=Your account is inactive")
        
        # Update last login
        user.last_login = datetime.utcnow()
        
        # Mark as SSO user if not already
        if not user.is_sso_user:
            user.is_sso_user = True
        
        db.session.commit()
        
        # Create JWT tokens
        access_token = create_access_token(
            identity=str(user.id),
            additional_claims={'role': user.role}
        )
        
        # Log activity
        activity = ActivityLog(
            event_type='saml_login',
            user_id=user.id,
            description=f'User {user.email} logged in via SAML SSO',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        db.session.add(activity)
        db.session.commit()
        
        current_app.logger.info(f"SAML login successful for: {email}")
        
        # Redirect to frontend with token
        frontend_url = current_app.config.get('FRONTEND_URL')
        return redirect(f"{frontend_url}/auth/saml-callback?token={access_token}")
        
    except Exception as e:
        current_app.logger.error(f"SAML ACS error: {e}", exc_info=True)
        frontend_url = current_app.config.get('FRONTEND_URL', 'http://localhost:3000')
        return redirect(f"{frontend_url}/auth/error?message=SAML authentication failed")


@auth_bp.route('/saml/metadata', methods=['GET'])
def saml_metadata():
    """
    Return SAML metadata for Service Provider (SP).
    This metadata should be provided to your Identity Provider.
    """
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
        from config.saml_settings import get_saml_settings
        
        saml_settings = get_saml_settings()
        auth = OneLogin_Saml2_Auth(
            prepare_flask_request(request),
            old_settings=saml_settings
        )
        
        settings = auth.get_settings()
        metadata = settings.get_sp_metadata()
        errors = settings.validate_metadata(metadata)
        
        if errors:
            current_app.logger.error(f"Metadata validation errors: {errors}")
            return jsonify({
                'error': {
                    'code': 'METADATA_ERROR',
                    'message': 'Invalid metadata',
                    'details': errors
                }
            }), 500
        
        return Response(metadata, mimetype='text/xml')
        
    except Exception as e:
        current_app.logger.error(f"Metadata generation error: {e}", exc_info=True)
        return jsonify({
            'error': {
                'code': 'METADATA_ERROR',
                'message': f'Failed to generate metadata: {str(e)}'
            }
        }), 500


@auth_bp.route('/saml/sls', methods=['GET', 'POST'])
def saml_sls():
    """
    SAML Single Logout Service (SLS).
    Handles logout requests from IdP.
    """
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
        from config.saml_settings import get_saml_settings
        
        saml_settings = get_saml_settings()
        auth = OneLogin_Saml2_Auth(
            prepare_flask_request(request),
            old_settings=saml_settings
        )
        
        # Process logout request/response
        url = auth.process_slo()
        errors = auth.get_errors()
        
        if errors:
            current_app.logger.error(f"SAML SLS errors: {errors}")
        
        # Redirect to frontend
        frontend_url = current_app.config.get('FRONTEND_URL')
        if url:
            return redirect(url)
        else:
            return redirect(f"{frontend_url}/login")
            
    except Exception as e:
        current_app.logger.error(f"SAML SLS error: {e}", exc_info=True)
        frontend_url = current_app.config.get('FRONTEND_URL', 'http://localhost:3000')
        return redirect(f"{frontend_url}/login")

