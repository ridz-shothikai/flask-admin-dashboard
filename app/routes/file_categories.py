from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from datetime import datetime
from urllib.parse import urlparse, urlunparse
import os
import requests
from typing import List, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from app.models import FileCategory, ActivityLog, User
from app.schemas.file_category_schema import (
    FileCategoryCreateSchema,
    FileCategoryUpdateSchema,
    FileCategoryQuerySchema,
    FetchCategoriesFromApplicationsSchema
)
from app.utils.validation import validate_json_body, validate_query_params

file_categories_bp = Blueprint('file_categories', __name__)

# Valid categories list (fallback when no categories are fetched)
VALID_CATEGORIES = [
    "1099",
    "CHECKS",
    "CHILD_WELFARE_REPORTS",
    "LEAVE_DOCUMENTS",
    "MONTH_END_REPORTS",
    "PAYROLL_REPORTS_N_DOCUMENTS",
    "PENDING_FILES",
    "PERSONNEL_FILES",
    "TRAVEL_REPORTS",
    "OTHER"
]


CATEGORY_FOLDER_PATHS = [
    "Georgia 14/Pending Files/",
    "Georgia 14/"
]


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


def require_superadmin():
    """Decorator to require superadmin role only"""
    claims = get_jwt()
    role = claims.get('role', 'user')
    if role != 'superadmin':
        return jsonify({
            'error': {
                'code': 'FORBIDDEN',
                'message': 'Superadmin access required'
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


def _parse_folder_error(error_message: str, status_code: int) -> str:
    """Parse folder creation error and return user-friendly message."""
    error_lower = error_message.lower()
    
    # Check for specific error patterns
    if 'already exists' in error_lower or 'exists' in error_lower:
        return "A folder with this name already exists in one or more locations. Please use a different category name."
    elif 'permission' in error_lower or 'access denied' in error_lower or 'forbidden' in error_lower:
        return "You do not have permission to create folders. Please contact an administrator."
    elif 'not found' in error_lower or 'invalid path' in error_lower:
        return "The destination path is invalid or does not exist. Please contact an administrator."
    elif 'timeout' in error_lower or status_code == 408:
        return "The folder creation service took too long to respond. Please try again."
    elif 'connection' in error_lower or 'network' in error_lower or status_code in (500, 502, 503, 504):
        return "The folder creation service is currently unavailable. Please try again in a few moments."
    else:
        return f"Failed to create folders: {error_message}"


def _create_category_folders(category_name: str, auth_token: str = None, timeout: int = 10) -> tuple:
    """
    Create category folders in required paths via application backend API.
    Returns (success: bool, error_message: str or None)
    """
    application_backend_url = (
        current_app.config.get('APPLICATION_BACKEND_URL')
        or os.environ.get('APPLICATION_BACKEND_URL')
    )
    create_folder_endpoint = (
        current_app.config.get('CREATE_FOLDER_ENDPOINT')
        or os.environ.get('CREATE_FOLDER_ENDPOINT')
    )

    if not application_backend_url:
        error_msg = "APPLICATION_BACKEND_URL is not configured. Please contact an administrator."
        current_app.logger.error("Folder creation configuration error: %s", error_msg)
        return False, error_msg

    if not create_folder_endpoint:
        error_msg = "Folder creation endpoint is not configured. Please contact an administrator."
        current_app.logger.error("Folder creation configuration error: %s", error_msg)
        return False, error_msg

    create_folder_url = f"{application_backend_url.rstrip('/')}/{create_folder_endpoint.lstrip('/')}"
    current_app.logger.info(
        "Starting folder creation for category '%s' using endpoint '%s' across %d paths",
        category_name,
        create_folder_url,
        len(CATEGORY_FOLDER_PATHS)
    )

    headers = {
        'Content-Type': 'application/json'
    }
    if auth_token:
        headers['Authorization'] = f'Bearer {auth_token}'

    for current_path in CATEGORY_FOLDER_PATHS:
        payload = {
            'folderName': category_name,
            'currentPath': current_path
        }
        current_app.logger.debug(
            "Creating folder for category '%s' at path '%s'",
            category_name,
            current_path
        )
        try:
            response = requests.post(
                create_folder_url,
                json=payload,
                headers=headers,
                timeout=timeout
            )
            if response.status_code in (200, 201):
                current_app.logger.info(
                    "Folder created for category '%s' at path '%s'",
                    category_name,
                    current_path
                )
            else:
                # Extract error message from response
                error_text = response.text[:500]
                try:
                    error_data = response.json()
                    if isinstance(error_data, dict):
                        error_text = error_data.get('message') or error_data.get('error') or error_text
                except (ValueError, requests.exceptions.JSONDecodeError):
                    pass
                
                user_message = _parse_folder_error(error_text, response.status_code)
                current_app.logger.error(
                    "Folder creation failed for category '%s' at path '%s'. Status: %s, Response: %s",
                    category_name,
                    current_path,
                    response.status_code,
                    error_text
                )
                return False, user_message
        except requests.exceptions.Timeout:
            error_msg = "The folder creation service took too long to respond. Please try again."
            current_app.logger.error("Folder creation timeout for category '%s' at path '%s'", category_name, current_path)
            return False, error_msg
        except requests.exceptions.ConnectionError:
            error_msg = "Unable to connect to folder creation service. Please try again in a few moments."
            current_app.logger.error("Folder creation connection error for category '%s' at path '%s'", category_name, current_path)
            return False, error_msg
        except requests.exceptions.RequestException as exc:
            error_msg = f"Unexpected error while creating folders: {str(exc)[:100]}"
            current_app.logger.error("Folder creation request error for category '%s' at path '%s': %s", category_name, current_path, str(exc))
            return False, error_msg
    
    # All folders created successfully
    current_app.logger.info("All folders created successfully for category '%s'", category_name)
    return True, None


@file_categories_bp.route('', methods=['GET'])
@jwt_required()
@validate_query_params(FileCategoryQuerySchema)
def get_file_categories(validated_data: FileCategoryQuerySchema):
    """Get all file categories with pagination and filtering"""
    # Get all file categories
    all_categories = FileCategory.get_all()
    
    # Apply filters
    filtered_categories = all_categories
    
    # Search filter
    if validated_data.search:
        search_term = validated_data.search.lower()
        filtered_categories = [
            cat for cat in filtered_categories
            if (hasattr(cat, 'code') and search_term in cat.code.lower()) or
               (hasattr(cat, 'name') and cat.name and search_term in cat.name.lower()) or
               (hasattr(cat, 'description') and cat.description and search_term in cat.description.lower())
        ]
    
    # Status filter
    if validated_data.status:
        filtered_categories = [cat for cat in filtered_categories if hasattr(cat, 'status') and cat.status == validated_data.status]
    
    # Sorting
    sort_field = validated_data.sort
    reverse = validated_data.order == 'desc'
    
    def get_sort_value(cat):
        if hasattr(cat, sort_field):
            value = getattr(cat, sort_field)
            if isinstance(value, datetime):
                return value.timestamp() if value else 0
            return value if value else ''
        return ''
    
    filtered_categories.sort(key=get_sort_value, reverse=reverse)
    
    # Pagination
    pagination = _paginate_firestore(filtered_categories, validated_data.page, validated_data.per_page)

    return jsonify({
        'file_categories': [cat.to_dict() for cat in pagination['items']],
        'pagination': {
            'page': validated_data.page,
            'per_page': validated_data.per_page,
            'total': pagination['total'],
            'pages': pagination['pages'],
            'has_next': pagination['has_next'],
            'has_prev': pagination['has_prev']
        }
    }), 200


@file_categories_bp.route('', methods=['POST'])
@jwt_required()
@validate_json_body(FileCategoryCreateSchema)
def create_file_category(validated_data: FileCategoryCreateSchema):
    """Create a new file category"""
    error = require_superadmin()
    if error:
        return error

    # Determine code: use provided code or generate from name
    if validated_data.code:
        # Normalize provided code to uppercase
        code = validated_data.code.upper()
    else:
        # Generate code from name: uppercase and replace spaces with underscores
        if not validated_data.name:
            return jsonify({
                'error': {
                    'code': 'VALIDATION_ERROR',
                    'message': 'Either code or name must be provided'
                }
            }), 400
        code = validated_data.name.upper().replace(' ', '_')
    
    # Check if code already exists
    if FileCategory.code_exists(code):
        return jsonify({
            'error': {
                'code': 'CATEGORY_EXISTS',
                'message': 'A file category with this code already exists'
            }
        }), 409

    # IMPORTANT: Create folders BEFORE saving category for transactional integrity
    # If folder creation fails, we don't create the category
    category_display_name = validated_data.name or code
    auth_header = request.headers.get('Authorization', '')
    auth_token = auth_header.split(' ', 1)[1] if auth_header.startswith('Bearer ') else None
    
    current_app.logger.info(
        "Attempting to create folders for new category '%s' before database save",
        category_display_name
    )
    
    folders_created, folder_error = _create_category_folders(category_display_name, auth_token=auth_token)
    
    if not folders_created:
        # Folder creation failed - do NOT create the category
        current_app.logger.error(
            "Folder creation failed for category '%s'. Error: %s. Category creation aborted.",
            category_display_name,
            folder_error
        )
        return jsonify({
            'error': {
                'code': 'FOLDER_CREATION_FAILED',
                'message': f'Failed to create category: {folder_error}'
            }
        }), 400

    # Folders created successfully - now create the category
    file_category = FileCategory(
        code=code,
        name=validated_data.name or code,
        description=validated_data.description,
        status=validated_data.status,
        short_code=validated_data.short_code if validated_data.short_code is not None else []
    )
    file_category.save()

    current_app.logger.info(
        "Category '%s' saved to database after successful folder creation",
        file_category.name or file_category.code
    )

    # Log activity
    current_user_id = get_jwt_identity()
    activity = ActivityLog(
        event_type='file_category_created',
        user_id=current_user_id,
        description=f'Created file category: {file_category.code}',
        ip_address=request.remote_addr
    )
    activity.save()

    return jsonify({
        'message': 'File category created successfully',
        'file_category': file_category.to_dict()
    }), 201

@file_categories_bp.route('/<category_id>', methods=['GET'])
@jwt_required()
def get_file_category(category_id):
    """Get a specific file category by ID"""
    file_category = FileCategory.get_by_id(category_id)
    if not file_category:
        return jsonify({
            'error': {
                'code': 'CATEGORY_NOT_FOUND',
                'message': f'File category with id {category_id} not found'
            }
        }), 404

    return jsonify(file_category.to_dict()), 200


@file_categories_bp.route('/<category_id>', methods=['PUT'])
@jwt_required()
@validate_json_body(FileCategoryUpdateSchema)
def update_file_category(category_id, validated_data: FileCategoryUpdateSchema):
    """Update a file category"""
    error = require_superadmin()
    if error:
        return error

    file_category = FileCategory.get_by_id(category_id)
    if not file_category:
        return jsonify({
            'error': {
                'code': 'CATEGORY_NOT_FOUND',
                'message': f'File category with id {category_id} not found'
            }
        }), 404

    # Update fields
    if validated_data.code:
        # Normalize code to uppercase
        code = validated_data.code.upper()
        # Check if new code already exists
        if FileCategory.code_exists(code, exclude_id=category_id):
            return jsonify({
                'error': {
                    'code': 'CATEGORY_EXISTS',
                    'message': 'A file category with this code already exists'
                }
            }), 409
        file_category.code = code

    if validated_data.name is not None:
        file_category.name = validated_data.name

    if validated_data.description is not None:
        file_category.description = validated_data.description

    if validated_data.status:
        file_category.status = validated_data.status

    if validated_data.short_code is not None:
        file_category.short_code = validated_data.short_code

    file_category.save()

    # Log activity
    current_user_id = get_jwt_identity()
    activity = ActivityLog(
        event_type='file_category_updated',
        user_id=current_user_id,
        description=f'Updated file category: {file_category.code}',
        ip_address=request.remote_addr
    )
    activity.save()

    return jsonify({
        'message': 'File category updated successfully',
        'file_category': file_category.to_dict()
    }), 200


@file_categories_bp.route('/<category_id>', methods=['DELETE'])
@jwt_required()
def delete_file_category(category_id):
    """Delete a file category"""
    error = require_superadmin()
    if error:
        return error

    file_category = FileCategory.get_by_id(category_id)
    if not file_category:
        return jsonify({
            'error': {
                'code': 'CATEGORY_NOT_FOUND',
                'message': f'File category with id {category_id} not found'
            }
        }), 404

    # Check if category is assigned to any users
    user_count = file_category.get_user_count()
    if user_count > 0:
        return jsonify({
            'error': {
                'code': 'CATEGORY_IN_USE',
                'message': f'Cannot delete file category. It is assigned to {user_count} user(s). Please unassign it from all users first.'
            }
        }), 400

    code = file_category.code
    file_category.delete()

    # Log activity
    current_user_id = get_jwt_identity()
    activity = ActivityLog(
        event_type='file_category_deleted',
        user_id=current_user_id,
        description=f'Deleted file category: {code}',
        ip_address=request.remote_addr
    )
    activity.save()

    return jsonify({
        'message': 'File category deleted successfully'
    }), 200


@file_categories_bp.route('/all', methods=['DELETE'])
@jwt_required()
def delete_all_file_categories():
    """Delete all file categories (Superadmin only)"""
    error = require_superadmin()
    if error:
        return error

    total_deleted = FileCategory.delete_all()

    # Log activity
    current_user_id = get_jwt_identity()
    activity = ActivityLog(
        event_type='file_categories_deleted_all',
        user_id=current_user_id,
        description=f'Deleted all file categories ({total_deleted})',
        ip_address=request.remote_addr
    )
    activity.save()

    return jsonify({
        'message': f'Successfully deleted {total_deleted} file categories'
    }), 200


def _convert_to_backend_url(application_url: str) -> str:
    """
    Convert application URL to backend URL format.
    Example: https://doc-digitization.shothik.ai/r2/login -> https://doc-digitization.shothik.ai/r14-backend
    """
    try:
        parsed = urlparse(application_url)
        # Reconstruct URL with base domain and /r14-backend path
        backend_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            '/r14-backend',
            '',  # params
            '',  # query
            ''   # fragment
        ))
        return backend_url
    except Exception as e:
        raise ValueError(f"Invalid URL format: {application_url}. Error: {str(e)}")


def _fetch_categories_from_backend(backend_url: str, auth_token: str = None, timeout: int = 10) -> List[str]:
    """
    Fetch categories from a backend URL.
    Uses the endpoint: /backend/api/v2/system/categories
    Returns a list of category code strings (e.g., ["1099", "OTHER", ...])
    
    Args:
        backend_url: The base backend URL
        auth_token: JWT token for authentication (optional)
        timeout: Request timeout in seconds
    """
    try:
        categories_url = f"{backend_url.rstrip('/')}/backend/api/v2/system/categories"
        print(f"DEBUG [file_categories.py]: categories_url = {categories_url}")
        
        # Prepare headers
        headers = {
            'Content-Type': 'application/json',
        }
        
        # Add Authorization header if token is provided
        if auth_token:
            headers['Authorization'] = f'Bearer {auth_token}'
        
        # Make request to fetch categories
        response = requests.get(
            categories_url,
            timeout=timeout,
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            # Backend returns a simple array of category code strings
            # e.g., ["1099", "OTHER", "PAYROLL_REPORTS_N_DOCUMENTS", ...]
            if isinstance(data, list):
                # Filter to ensure all items are strings
                return [str(cat).strip() for cat in data if cat and str(cat).strip()]
            else:
                print(f"DEBUG [file_categories.py]: Unexpected response format: {type(data)}")
                return []
        else:
            # Log error details for debugging
            print(f"DEBUG [file_categories.py]: Request failed with status {response.status_code}")
            try:
                error_data = response.json()
                print(f"DEBUG [file_categories.py]: Error response: {error_data}")
            except (ValueError, requests.exceptions.JSONDecodeError):
                print(f"DEBUG [file_categories.py]: Error response text: {response.text[:200]}")
            return []
    except requests.exceptions.RequestException as e:
        # Log error but don't fail the entire request
        print(f"DEBUG [file_categories.py]: Request exception: {str(e)}")
        return []
    except Exception as e:
        # Log error but don't fail the entire request
        print(f"DEBUG [file_categories.py]: Unexpected error: {str(e)}")
        return []


@file_categories_bp.route('/from-applications', methods=['POST'])
@jwt_required()
@validate_json_body(FetchCategoriesFromApplicationsSchema)
def fetch_categories_from_applications(validated_data: FetchCategoriesFromApplicationsSchema):
    """
    Fetch unique categories from multiple applications.
    
    Accepts a list of application URLs, converts them to backend URLs,
    fetches categories from each, and returns unique categories.
    """
    application_urls = validated_data.application_urls
    errors = []
    
    # Extract JWT token from Authorization header
    auth_header = request.headers.get('Authorization', '')
    auth_token = None
    if auth_header.startswith('Bearer '):
        auth_token = auth_header.split(' ', 1)[1]
    
    # Track unique categories using a set (case-insensitive)
    unique_categories: Set[str] = set()
    
    # Parallelize backend requests for faster response
    def fetch_from_url(app_url: str):
        """Helper function to fetch categories from a single URL"""
        try:
            backend_url = _convert_to_backend_url(app_url)
            categories = _fetch_categories_from_backend(backend_url, auth_token=auth_token)
            return app_url, categories, None
        except Exception as e:
            return app_url, [], str(e)
    
    # Use ThreadPoolExecutor to fetch from all URLs in parallel
    with ThreadPoolExecutor(max_workers=min(len(application_urls), 10)) as executor:
        future_to_url = {executor.submit(fetch_from_url, app_url): app_url for app_url in application_urls}
        
        for future in as_completed(future_to_url):
            app_url, categories, error = future.result()
            
            if error:
                errors.append({
                    'url': app_url,
                    'error': error
                })
            else:
                # Add to unique categories set (case-insensitive deduplication)
                for category_code in categories:
                    if category_code:
                        # Normalize to uppercase for case-insensitive uniqueness check
                        unique_categories.add(category_code.upper())
    
    # Convert to sorted list of category codes
    unique_categories_list = sorted(unique_categories)
    
    # If no categories were fetched, use VALID_CATEGORIES as fallback
    if not unique_categories_list:
        unique_categories_list = sorted([cat.upper() for cat in VALID_CATEGORIES])
    
    # Batch load all categories from database for better performance
    all_categories = FileCategory.get_all()
    
    # Create a lookup map by code (uppercase for case-insensitive matching)
    categories_by_code = {}
    for cat in all_categories:
        if hasattr(cat, 'code') and cat.code:
            categories_by_code[cat.code.upper()] = cat
    
    # Pre-calculate user counts in a single pass for all categories
    from app.models.user import User
    all_users = User.get_all()
    category_user_counts = {}
    for user in all_users:
        if hasattr(user, 'assigned_file_category_ids') and user.assigned_file_category_ids:
            for cat_id in user.assigned_file_category_ids:
                category_user_counts[cat_id] = category_user_counts.get(cat_id, 0) + 1
    
    # Build response list with pre-calculated user counts
    file_categories_list = []
    for category_code in unique_categories_list:
        category = categories_by_code.get(category_code)
        if category:
            # Use pre-calculated user_count for better performance
            user_count = category_user_counts.get(category.id, 0)
            file_categories_list.append(category.to_dict(user_count=user_count))
        # Remove the else block - simply skip categories not in DB
    
    # Sort by code for consistent output
    file_categories_list.sort(key=lambda x: x.get('code', '').upper())
    
    # Return in same format as get_file_categories
    response_data = {
        'file_categories': file_categories_list,
        'pagination': {
            'page': 1,
            'per_page': len(file_categories_list),
            'total': len(file_categories_list),
            'pages': 1,
            'has_next': False,
            'has_prev': False
        },
        'applications_processed': len(application_urls) - len(errors),
        'applications_failed': len(errors)
    }
    
    if errors:
        response_data['errors'] = errors
    
    return jsonify(response_data), 200


@file_categories_bp.route('/accessible', methods=['GET'])
@jwt_required()
def get_accessible_categories():
    """Get file categories accessible to the authenticated user"""
    # Get current user
    user_id = get_jwt_identity()
    user = User.get_by_id(user_id)
    
    if not user:
        return jsonify({
            'error': {
                'code': 'USER_NOT_FOUND',
                'message': 'User not found'
            }
        }), 404
    
    # Get user's assigned file category IDs
    category_ids = getattr(user, 'assigned_file_category_ids', [])
    
    if not category_ids:
        return jsonify({
            'categories': []
        }), 200

    # Fetch categories in bulk to avoid one database call per ID.
    unique_category_ids = list(dict.fromkeys(category_ids))
    categories = FileCategory.get_by_ids(unique_category_ids)
    categories_by_id = {category.id: category for category in categories}

    accessible_categories = []
    for category_id in category_ids:
        category = categories_by_id.get(category_id)
        if category:
            # Only return active categories
            if hasattr(category, 'status') and category.status == 'active':
                accessible_categories.append({
                    'id': category.id,
                    'code': category.code,
                    'name': category.name if hasattr(category, 'name') and category.name else category.code,
                    'description': category.description if hasattr(category, 'description') else None,
                    'short_code': category.short_code if hasattr(category, 'short_code') and category.short_code else []
                })
    
    return jsonify({
        'categories': accessible_categories
    }), 200


@file_categories_bp.route('/all', methods=['GET'])
def get_all_categories_api_key():
    """Get all file categories (API key authentication) - Returns only name, code, and short_code"""
    # Get API key from headers
    api_key = request.headers.get('X-API-Key') or request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not api_key:
        return jsonify({
            'error': {
                'code': 'UNAUTHORIZED',
                'message': 'API key is required. Provide it in X-API-Key header or Authorization header.'
            }
        }), 401
    
    # Validate API key against JWT_SECRET_KEY
    jwt_secret = current_app.config.get('JWT_SECRET_KEY')
    if api_key != jwt_secret:
        return jsonify({
            'error': {
                'code': 'UNAUTHORIZED',
                'message': 'Invalid API key'
            }
        }), 401
    
    return jsonify({
        'categories': FileCategory.get_active_summaries()
    }), 200


@file_categories_bp.route('/all/jwt', methods=['GET'])
@jwt_required()
def get_all_categories_jwt():
    """Get all active file categories (JWT authentication) - Returns only id, name, code, and short_code"""
    return jsonify({
        'categories': FileCategory.get_active_summaries()
    }), 200

