from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from datetime import datetime
from app.models import User, ActivityLog
from app.schemas.user_schema import (
    UserCreateSchema,
    UserUpdateSchema,
    UserQuerySchema,
    InitSuperuserSchema
)
from app.models import FileCategory
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


@users_bp.route('', methods=['GET'])
@jwt_required()
@validate_query_params(UserQuerySchema)
def get_users(validated_data: UserQuerySchema):
    """Get all users with pagination and filtering"""
    error = require_superadmin()
    if error:
        return error

    # Get all users (Firestore doesn't support complex queries easily)
    all_users = User.get_all()
    
    # Collect all unique application IDs and file category IDs from all users
    # Also pre-calculate user counts in a single pass for performance
    all_app_ids = set()
    all_category_ids = set()
    app_user_counts = {}  # app_id -> count
    category_user_counts = {}  # category_id -> count
    
    for user in all_users:
        # Count applications
        if hasattr(user, 'assigned_application_ids') and user.assigned_application_ids:
            all_app_ids.update(user.assigned_application_ids)
            for app_id in user.assigned_application_ids:
                app_user_counts[app_id] = app_user_counts.get(app_id, 0) + 1
        
        # Count file categories
        if hasattr(user, 'assigned_file_category_ids') and user.assigned_file_category_ids:
            all_category_ids.update(user.assigned_file_category_ids)
            for cat_id in user.assigned_file_category_ids:
                category_user_counts[cat_id] = category_user_counts.get(cat_id, 0) + 1
    
    # Batch load all applications and file categories for performance
    from app.db import get_db
    db = get_db()
    
    applications_cache = {}
    if all_app_ids:
        from app.models.application import Application
        # Use Firestore batch get for better performance
        app_refs = [db.collection('applications').document(app_id) for app_id in all_app_ids]
        if app_refs:
            docs = db.get_all(app_refs)
            for doc in docs:
                if doc.exists:
                    data = doc.to_dict()
                    data['id'] = doc.id
                    app = Application(**data)
                    applications_cache[app.id] = app
    
    file_categories_cache = {}
    if all_category_ids:
        from app.models.file_category import FileCategory
        # Use Firestore batch get for better performance
        category_refs = [db.collection('file_categories').document(cat_id) for cat_id in all_category_ids]
        if category_refs:
            docs = db.get_all(category_refs)
            for doc in docs:
                if doc.exists:
                    data = doc.to_dict()
                    data['id'] = doc.id
                    category = FileCategory(**data)
                    file_categories_cache[category.id] = category
    
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
    
    # File category filter
    if validated_data.category:
        category_ids_set = set(validated_data.category)
        filtered_users = [
            u for u in filtered_users
            if hasattr(u, 'assigned_file_category_ids') and 
               u.assigned_file_category_ids and
               any(cat_id in category_ids_set for cat_id in u.assigned_file_category_ids)
        ]
    
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
        'users': [
            user.to_dict(
                applications_cache=applications_cache,
                file_categories_cache=file_categories_cache,
                app_user_counts=app_user_counts,
                category_user_counts=category_user_counts
            ) for user in pagination['items']
        ],
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
    error = require_superadmin()
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

    # Batch load file categories for validation and reuse for response
    from app.db import get_db
    from app.models.application import Application
    db = get_db()
    file_categories_dict = {}
    
    if validated_data.file_category_ids:
        # Batch load all file categories
        category_refs = [db.collection('file_categories').document(cat_id) for cat_id in validated_data.file_category_ids]
        if category_refs:
            docs = db.get_all(category_refs)
            for doc in docs:
                if doc.exists:
                    data = doc.to_dict()
                    data['id'] = doc.id
                    category = FileCategory(**data)
                    file_categories_dict[category.id] = category
        
        # Validate file category IDs
        invalid_ids = []
        for category_id in validated_data.file_category_ids:
            category = file_categories_dict.get(category_id)
            if not category:
                invalid_ids.append(category_id)
            elif hasattr(category, 'status') and category.status != 'active':
                invalid_ids.append(category_id)
        if invalid_ids:
            return jsonify({
                'error': {
                    'code': 'INVALID_FILE_CATEGORY_IDS',
                    'message': f'Invalid or inactive file category IDs: {invalid_ids}. Please use valid active category IDs.'
                }
            }), 400

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

    # Assign file categories
    if validated_data.file_category_ids:
        user.assigned_file_category_ids = validated_data.file_category_ids

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

    # Batch load applications for response (if needed)
    applications_cache = {}
    if validated_data.application_ids:
        app_refs = [db.collection('applications').document(app_id) for app_id in validated_data.application_ids]
        if app_refs:
            docs = db.get_all(app_refs)
            for doc in docs:
                if doc.exists:
                    data = doc.to_dict()
                    data['id'] = doc.id
                    app = Application(**data)
                    applications_cache[app.id] = app
    
    # Reuse already loaded file categories for response
    file_categories_cache = file_categories_dict

    # Calculate user counts efficiently by loading all users once and counting in memory
    app_user_counts = {}
    category_user_counts = {}
    
    if validated_data.application_ids or validated_data.file_category_ids:
        # Initialize counts for the applications/categories we care about
        app_ids_set = set(validated_data.application_ids) if validated_data.application_ids else set()
        cat_ids_set = set(validated_data.file_category_ids) if validated_data.file_category_ids else set()
        
        for app_id in app_ids_set:
            app_user_counts[app_id] = 0
        for cat_id in cat_ids_set:
            category_user_counts[cat_id] = 0
        
        # Load all users once (much faster than N+M individual Firestore queries)
        all_users = User.get_all()
        
        # Count in a single pass through all users
        for u in all_users:
            if hasattr(u, 'assigned_application_ids') and u.assigned_application_ids:
                for app_id in u.assigned_application_ids:
                    if app_id in app_ids_set:
                        app_user_counts[app_id] += 1
            
            if hasattr(u, 'assigned_file_category_ids') and u.assigned_file_category_ids:
                for cat_id in u.assigned_file_category_ids:
                    if cat_id in cat_ids_set:
                        category_user_counts[cat_id] += 1

    return jsonify({
        'message': 'User created successfully',
        'user': user.to_dict(
            applications_cache=applications_cache if applications_cache else None,
            file_categories_cache=file_categories_cache if file_categories_cache else None,
            app_user_counts=app_user_counts if app_user_counts else None,
            category_user_counts=category_user_counts if category_user_counts else None
        )
    }), 201


@users_bp.route('/<user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    """Get a specific user by ID"""
    error = require_superadmin()
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
    error = require_superadmin()
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

    # Update file categories
    if validated_data.file_category_ids is not None:
        # Validate file category IDs exist in database
        invalid_ids = []
        for category_id in validated_data.file_category_ids:
            category = FileCategory.get_by_id(category_id)
            if not category:
                invalid_ids.append(category_id)
            elif hasattr(category, 'status') and category.status != 'active':
                invalid_ids.append(category_id)
        if invalid_ids:
            return jsonify({
                'error': {
                    'code': 'INVALID_FILE_CATEGORY_IDS',
                    'message': f'Invalid or inactive file category IDs: {invalid_ids}. Please use valid active category IDs.'
                }
            }), 400
        user.assigned_file_category_ids = validated_data.file_category_ids

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
    error = require_superadmin()
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
    error = require_superadmin()
    if error:
        return error
    
    return jsonify({
        'roles': [
            {'value': 'user', 'label': 'User'},
            {'value': 'admin', 'label': 'Admin'},
            {'value': 'superadmin', 'label': 'Super Admin'},
            {'value': 'manager', 'label': 'Manager'},
            {'value': 'clark', 'label': 'Clark'}
        ]
    }), 200


@users_bp.route('/file-categories', methods=['GET'])
@jwt_required()
def get_file_categories():
    """Get all available file categories"""
    error = require_superadmin()
    if error:
        return error
    
    # Get all active file categories from database
    all_categories = FileCategory.get_all()
    active_categories = [
        cat for cat in all_categories 
        if hasattr(cat, 'status') and cat.status == 'active'
    ]
    
    return jsonify({
        'file_categories': [
            {
                'value': cat.code,
                'label': cat.name if hasattr(cat, 'name') and cat.name else cat.code.replace('_', ' ').title()
            }
            for cat in active_categories
        ]
    }), 200


@users_bp.route('/init', methods=['POST'])
@validate_json_body(InitSuperuserSchema)
def init_superuser(validated_data: InitSuperuserSchema):
    """Initialize superuser - only works if no users exist in the database"""
    # Check if any users exist
    existing_users = User.get_all()
    if len(existing_users) > 0:
        return jsonify({
            'error': {
                'code': 'INITIALIZATION_FAILED',
                'message': 'Initialization can only be performed when no users exist in the database'
            }
        }), 403
    
    # Check if email already exists (shouldn't happen, but just in case)
    if User.email_exists(validated_data.email):
        return jsonify({
            'error': {
                'code': 'EMAIL_EXISTS',
                'message': 'A user with this email already exists'
            }
        }), 409
    
    # Create superuser
    user = User(
        email=validated_data.email,
        role='superadmin',
        status='active',
        first_name=validated_data.first_name,
        last_name=validated_data.last_name
    )
    user.set_password(validated_data.password)
    user.save()
    
    return jsonify({
        'message': 'Superuser created successfully',
        'user': user.to_dict()
    }), 201
