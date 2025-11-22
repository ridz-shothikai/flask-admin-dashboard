from flask import Blueprint, request, jsonify, current_app, redirect
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity
)
import jwt
import os
import base64
import xml.etree.ElementTree as ET
import re
import traceback
import logging
from datetime import datetime
from app.models import User, ActivityLog
from app.schemas.user_schema import LoginSchema
from app.utils.validation import validate_json_body
from app.utils.saml_utils import prepare_flask_request, load_saml_settings_from_json, get_saml_settings

# Configure logger
logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


def find_user_by_email(email):
    """Find user by email and return as dictionary"""
    user = User.get_by_email(email)
    if user:
        return {
            'id': user.id,
            'email': user.email,
            'role': user.role,
            'status': user.status,
            'first_name': getattr(user, 'first_name', None),
            'last_name': getattr(user, 'last_name', None)
        }
    return None


# ============================================================================
# SAML/SSO AUTHENTICATION ROUTES
# ============================================================================

# CRASH-SAFE TEST ROUTES

@auth_bp.route('/test/ping', methods=["GET"])
def test_ping():
    """Simple test route"""
    return jsonify({"msg": "Auth routes working", "status": "ok"}), 200


@auth_bp.route('/test/saml-imports', methods=["GET"])
def test_saml_imports():
    """Test if SAML libraries can be imported"""
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
        from onelogin.saml2.settings import OneLogin_Saml2_Settings
        
        return jsonify({
            "msg": "SAML imports successful",
            "saml_auth_class": str(OneLogin_Saml2_Auth),
            "saml_settings_class": str(OneLogin_Saml2_Settings),
            "status": "imports_ok"
        }), 200
    except Exception as e:
        return jsonify({
            "msg": "SAML import failed",
            "error": str(e),
            "error_type": type(e).__name__,
            "status": "import_error"
        }), 500


@auth_bp.route('/test/saml-settings', methods=["GET"])
def test_saml_settings():
    """Test if SAML settings can be loaded"""
    try:
        json_settings = load_saml_settings_from_json()
        hardcoded_settings = get_saml_settings()
        
        return jsonify({
            "msg": "SAML settings test",
            "json_settings_loaded": json_settings is not None,
            "hardcoded_settings_loaded": hardcoded_settings is not None,
            "json_settings_keys": list(json_settings.keys()) if json_settings else None,
            "hardcoded_settings_keys": list(hardcoded_settings.keys()) if hardcoded_settings else None,
            "status": "settings_test_complete"
        }), 200
    except Exception as e:
        return jsonify({
            "msg": "SAML settings test failed",
            "error": str(e),
            "error_type": type(e).__name__,
            "status": "settings_error"
        }), 500


# SSO Login route

@auth_bp.route('/sso/login')
def sso_login():
    try:
        logger.info("SSO LOGIN CALLED")
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
        
        saml_settings = load_saml_settings_from_json()
        if not saml_settings:
            saml_settings = get_saml_settings()
        
        auth = OneLogin_Saml2_Auth(prepare_flask_request(request), old_settings=saml_settings)
        login_url = auth.login()
        logger.info(f"Redirecting to: {login_url}")
        return redirect(login_url)
    except Exception as e:
        logger.error(f"SSO Login failed: {e}")
        logger.error(f"Error traceback: {traceback.format_exc()}")
        return jsonify({"msg": "SSO login failed", "error": str(e)}), 500


# SAFE ACS ROUTE - Manual SAML Response Parsing (Bypass Library)

@auth_bp.route('/sso/acs', methods=["POST"])
def sso_acs():
    logger.info("=" * 80)
    logger.info("SSO ACS ENDPOINT CALLED - MANUAL PARSING MODE")
    logger.info("PURPOSE: Process SAML response from IdP and extract user email")
    logger.info("=" * 80)
    
    try:
        logger.info("\nSTEP 1: INITIAL SAFETY CHECKS")
        logger.info("Checking if form data exists...")
        
        # Immediate safety checks
        if not request.form:
            logger.error("RESULT: No form data received from request")
            return jsonify({"msg": "No form data received"}), 400
        
        logger.info(f"RESULT: Form data found with keys: {list(request.form.keys())}")
        
        logger.info("\nChecking for SAMLResponse in form data...")
        if 'SAMLResponse' not in request.form:
            logger.error("RESULT: No SAMLResponse field found in form data")
            return jsonify({"msg": "No SAMLResponse found"}), 400
        
        logger.info("RESULT: SAMLResponse field found in form data")
        
        logger.info("\nSTEP 2: EXTRACTING SAML RESPONSE")
        logger.info("Getting base64-encoded SAML response from form...")
        saml_response_b64 = request.form['SAMLResponse']
        logger.info(f"RESULT: SAML response extracted (length: {len(saml_response_b64)} characters)")
        logger.info(f"First 100 characters of base64 response: {saml_response_b64[:100]}...")
        
        logger.info("\nSTEP 3: DECODING SAML RESPONSE")
        logger.info("Importing required libraries for decoding...")
        
        try:
            logger.info("RESULT: Required libraries imported successfully")
            
            logger.info("\nDecoding base64 SAML response to XML...")
            saml_response_xml = base64.b64decode(saml_response_b64)
            logger.info(f"RESULT: Base64 decoded successfully (XML length: {len(saml_response_xml)} bytes)")
            
            logger.info("\nParsing XML string into ElementTree...")
            root = ET.fromstring(saml_response_xml)
            logger.info(f"RESULT: XML parsed successfully (root tag: {root.tag})")
            
            logger.info("\nConverting XML bytes to readable string for debugging...")
            xml_str = saml_response_xml.decode('utf-8', errors='ignore')
            logger.info("RESULT: XML converted to string successfully")
            logger.info(f"RAW SAML RESPONSE (first 500 chars):\n{xml_str[:500]}...")
            
        except Exception as decode_error:
            logger.error(f"RESULT: Manual decode failed with error: {decode_error}")
            logger.error(f"ERROR TYPE: {type(decode_error).__name__}")
            return jsonify({"msg": "Failed to decode SAML response", "error": str(decode_error)}), 400
        
        logger.info("\nSTEP 4: EMAIL EXTRACTION PROCESS")
        logger.info("PURPOSE: Extract user email from SAML response using multiple methods")
        email = None
        
        try:
            logger.info("\nSetting up XML namespaces for SAML parsing...")
            # Define XML namespaces commonly used in SAML
            namespaces = {
                'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion',
                'saml2p': 'urn:oasis:names:tc:SAML:2.0:protocol',
                'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
                'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'
            }
            logger.info("RESULT: XML namespaces configured")
            logger.info(f"Namespaces: {list(namespaces.keys())}")
            
            logger.info("\nSTEP 4A: METHOD 1 - SEARCHING FOR NAMEID")
            logger.info("Trying to find NameID element (primary user identifier)...")
            
            nameid_paths = [
                './/saml2:NameID',
                './/saml:NameID',
                './/NameID'
            ]
            logger.info(f"Will try these XPath patterns: {nameid_paths}")
            
            for i, path in enumerate(nameid_paths, 1):
                try:
                    logger.info(f"\nAttempt {i}: Searching with pattern '{path}'...")
                    nameid_element = root.find(path, namespaces)
                    if nameid_element is not None:
                        logger.info(f"FOUND: NameID element found with pattern '{path}'")
                        if nameid_element.text:
                            email = nameid_element.text
                            logger.info(f"SUCCESS: Email extracted from NameID: {email}")
                            logger.info(f"NameID Format: {nameid_element.get('Format', 'Not specified')}")
                            break
                        else:
                            logger.warning("WARNING: NameID element found but contains no text")
                    else:
                        logger.info(f"RESULT: No NameID found with pattern '{path}'")
                except Exception as e:
                    logger.error(f"ERROR: Exception while searching with pattern '{path}': {e}")
                    continue
            
            if email:
                logger.info(f"\nMETHOD 1 SUCCESS: Email found via NameID: {email}")
            else:
                logger.info("\nMETHOD 1 FAILED: No email found in NameID elements")
            
            logger.info("\nSTEP 4B: METHOD 2 - SEARCHING IN ATTRIBUTES")
            logger.info("Searching for email in SAML attributes...")
            
            if not email:
                attribute_paths = [
                    './/saml2:Attribute',
                    './/saml:Attribute',
                    './/Attribute'
                ]
                logger.info(f"Will try these attribute XPath patterns: {attribute_paths}")
                
                for i, attr_path in enumerate(attribute_paths, 1):
                    try:
                        logger.info(f"\nAttempt {i}: Searching attributes with pattern '{attr_path}'...")
                        attributes = root.findall(attr_path, namespaces)
                        logger.info(f"FOUND: {len(attributes)} attribute(s) found with pattern '{attr_path}'")
                        
                        for j, attr in enumerate(attributes, 1):
                            attr_name = attr.get('Name', 'Unknown')
                            logger.info(f"\nExamining attribute {j}: '{attr_name}'")
                            
                            # Common email attribute names
                            email_keywords = ['email', 'mail', 'emailaddress']
                            attr_name_lower = attr_name.lower()
                            
                            logger.info(f"Checking if '{attr_name_lower}' contains email keywords: {email_keywords}")
                            
                            if any(email_attr in attr_name_lower for email_attr in email_keywords):
                                logger.info(f"MATCH: Attribute '{attr_name}' appears to be an email field")
                                
                                # Try different value element patterns
                                value_patterns = [
                                    ('.//saml2:AttributeValue', namespaces),
                                    ('.//saml:AttributeValue', namespaces),
                                    ('.//AttributeValue', {})
                                ]
                                
                                for k, (pattern, ns) in enumerate(value_patterns, 1):
                                    logger.info(f"Attempt {k}: Looking for value with pattern '{pattern}'...")
                                    value_element = attr.find(pattern, ns)
                                    
                                    if value_element is not None and value_element.text:
                                        email = value_element.text
                                        logger.info(f"SUCCESS: Email found in attribute '{attr_name}': {email}")
                                        break
                                    else:
                                        logger.info(f"No value found with pattern '{pattern}'")
                                
                                if email:
                                    break
                            else:
                                logger.info(f"SKIP: Attribute '{attr_name}' doesn't appear to be email-related")
                        
                        if email:
                            break
                            
                    except Exception as e:
                        logger.error(f"ERROR: Exception while searching attributes with pattern '{attr_path}': {e}")
                        continue
                
                if email:
                    logger.info(f"\nMETHOD 2 SUCCESS: Email found via attributes: {email}")
                else:
                    logger.info("\nMETHOD 2 FAILED: No email found in attributes")
            else:
                logger.info("\nSKIPPING METHOD 2: Email already found via NameID")
            
            logger.info("\nSTEP 4C: METHOD 3 - REGEX SEARCH")
            logger.info("Searching for email patterns in entire XML content...")
            
            if not email:
                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                logger.info(f"Using regex pattern: {email_pattern}")
                
                email_matches = re.findall(email_pattern, xml_str)
                logger.info(f"FOUND: {len(email_matches)} email-like strings in XML")
                
                if email_matches:
                    email = email_matches[0]  # Take the first email found
                    logger.info(f"SUCCESS: Email found via regex: {email}")
                    if len(email_matches) > 1:
                        logger.info(f"Other emails found: {email_matches[1:]}")
                else:
                    logger.info("RESULT: No email patterns found in XML content")
                
                if email:
                    logger.info(f"\nMETHOD 3 SUCCESS: Email found via regex: {email}")
                else:
                    logger.info("\nMETHOD 3 FAILED: No email found via regex")
            else:
                logger.info("\nSKIPPING METHOD 3: Email already found")
            
            logger.info("\nSTEP 4D: DEBUGGING - LISTING ALL ATTRIBUTES")
            logger.info("Extracting all available attributes for debugging...")
            
            if not email:
                logger.info("PURPOSE: Since no email found, listing all attributes to help debug")
                try:
                    attribute_paths = [
                        './/saml2:Attribute',
                        './/saml:Attribute',
                        './/Attribute'
                    ]
                    
                    all_attributes_found = False
                    
                    for attr_path in attribute_paths:
                        attributes = root.findall(attr_path, namespaces)
                        if attributes:
                            all_attributes_found = True
                            logger.info(f"\nAttributes found with pattern '{attr_path}':")
                            
                            for i, attr in enumerate(attributes, 1):
                                attr_name = attr.get('Name', 'Unknown')
                                
                                # Try to get value
                                value_element = attr.find('.//saml2:AttributeValue', namespaces) or \
                                              attr.find('.//saml:AttributeValue', namespaces) or \
                                              attr.find('.//AttributeValue')
                                
                                value = value_element.text if value_element is not None else 'No value'
                                logger.info(f"  {i}. {attr_name}: {value}")
                    
                    if not all_attributes_found:
                        logger.error("RESULT: No attributes found with any pattern")
                        
                except Exception as debug_error:
                    logger.error(f"ERROR: Could not extract attributes for debugging: {debug_error}")
            else:
                logger.info("SKIPPING DEBUG LISTING: Email already found")
            
        except Exception as parse_error:
            logger.error(f"\nCRITICAL ERROR during email extraction: {parse_error}")
            logger.error(f"ERROR TYPE: {type(parse_error).__name__}")
            logger.error(f"FULL TRACEBACK:\n{traceback.format_exc()}")
        
        logger.info("\nSTEP 5: EMAIL VALIDATION AND FALLBACK")
        logger.info("Checking final email result...")
        
        # Use fallback email if extraction failed
        if not email:
            # Redirect user to frontend fallback page
            frontend_uri = os.getenv("FRONTEND_URL", "http://localhost:3000")
            logger.info(f"Frontend URL from environment: {frontend_uri}")
            
            redirect_uri = f"{frontend_uri}/sso-callback-error?message=User not Found"
            logger.info("RESULT: Redirect URL constructed")
            logger.info(f"Full redirect URL: {redirect_uri}")
            return redirect(redirect_uri)
        else:
            logger.info("SUCCESS: Email validation passed")
        
        logger.info(f"\nFINAL RESULT: Email to use for JWT: {email}")
        
        logger.info("\nSTEP 6: JWT TOKEN CREATION")
        logger.info("Creating JWT access token for user...")
        
        # get name from email
        email_name = email.split('@')[0]
        logger.info(f"Extracted name from email: {email_name}")
        
        logger.info("\nSTEP 7: PREPARING REDIRECT RESPONSE")
        logger.info("Building redirect URL for frontend...")
        
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
        logger.info(f"Frontend URL from environment: {frontend_url}")
        
        # Check this user is already registered or not 
        user = find_user_by_email(email)
        if not user:
            logger.warning(f"WARNING: User '{email}' not found in database")
            # Redirect user to frontend fallback page
            frontend_uri2 = os.getenv("FRONTEND_URL", "http://localhost:3000")
            logger.info(f"Frontend URL from environment: {frontend_uri2}")
            
            redirect_uri2 = f"{frontend_uri2}/sso-callback-error?message=User '{email}' Not found in the system"
            logger.info("RESULT: Redirect URL constructed")
            logger.info(f"Full redirect URL: {redirect_uri2}")
            return redirect(redirect_uri2)
        else:
            logger.info(f"RESULT: User '{email}' already exists in database")
            
            user_role = user.get('role')
            logger.info(f"User role found: {user_role}")
            
            # Get user object for activity logging
            user_obj = User.get_by_email(email)
            
            # Update last login
            if user_obj:
                user_obj.last_login = datetime.utcnow()
                user_obj.save()
                
                # Log activity
                activity = ActivityLog(
                    event_type='user_login',
                    user_id=user_obj.id,
                    description=f'User {email} logged in via SSO',
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent')
                )
                activity.save()
            
            access_token = create_access_token(
                identity=str(user.get('id')),
                additional_claims={"role": user_role, "name": email_name}
            )
            logger.info("RESULT: JWT token created successfully")
            logger.info(f"Token length: {len(access_token)} characters")
            logger.info(f"JWT token created successfully for: {email}")
            
            redirect_url = f"{frontend_url}/sso-callback?token={access_token}"
            logger.info("RESULT: Redirect URL constructed")
            logger.info(f"Full redirect URL: {redirect_url}")
            
            logger.info(f"Redirecting to: {redirect_url}")
            
            logger.info("\nOVERALL SUCCESS: SSO ACS processing completed successfully")
            logger.info(f"User '{email}' will be redirected to frontend with valid JWT token")
            logger.info("=" * 80)
            
            return redirect(redirect_url)
        
    except Exception as e:
        logger.error("\nCRITICAL SYSTEM ERROR occurred")
        logger.error(f"Error message: {str(e)}")
        logger.error(f"Error type: {type(e).__name__}")
        logger.error(f"Full traceback:\n{traceback.format_exc()}")
        
        logger.error(f"SSO ACS error: {str(e)}", exc_info=True)
        
        return jsonify({
            "msg": "SSO processing failed",
            "error": str(e),
            "error_type": type(e).__name__
        }), 500
    
    finally:
        logger.info("\nSSO ACS ENDPOINT FINISHED")
        logger.info("Cleanup completed")
        logger.info("=" * 80)


# ============================================================================
# TRADITIONAL AUTHENTICATION ROUTES
# ============================================================================

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
