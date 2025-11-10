from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from app import db
from app.models import Application, ActivityLog
from app.schemas.application_schema import (
    ApplicationCreateSchema,
    ApplicationUpdateSchema,
    ApplicationQuerySchema
)
from app.utils.validation import validate_json_body, validate_query_params

applications_bp = Blueprint('applications', __name__, url_prefix='/api/applications')


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


@applications_bp.route('', methods=['GET'])
@jwt_required()
@validate_query_params(ApplicationQuerySchema)
def get_applications(validated_data: ApplicationQuerySchema):
    """Get all applications with pagination and filtering"""
    # Build query
    query = Application.query

    # Search filter
    if validated_data.search:
        search_term = f"%{validated_data.search}%"
        query = query.filter(Application.name.ilike(search_term))

    # Status filter
    if validated_data.status:
        query = query.filter_by(status=validated_data.status)

    # Sorting
    sort_column = getattr(Application, validated_data.sort, Application.name)
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
        'applications': [app.to_dict() for app in pagination.items],
        'pagination': {
            'page': validated_data.page,
            'per_page': validated_data.per_page,
            'total': pagination.total,
            'pages': pagination.pages,
            'has_next': pagination.has_next,
            'has_prev': pagination.has_prev
        }
    }), 200


@applications_bp.route('', methods=['POST'])
@jwt_required()
@validate_json_body(ApplicationCreateSchema)
def create_application(validated_data: ApplicationCreateSchema):
    """Create a new application"""
    error = require_admin()
    if error:
        return error

    # Check if name already exists
    if Application.query.filter_by(name=validated_data.name).first():
        return jsonify({
            'error': {
                'code': 'APPLICATION_EXISTS',
                'message': 'An application with this name already exists'
            }
        }), 409

    # Create application
    application = Application(
        name=validated_data.name,
        description=validated_data.description,
        url=str(validated_data.url) if validated_data.url else None,
        status=validated_data.status
    )
    db.session.add(application)
    db.session.commit()

    # Log activity
    current_user_id = get_jwt_identity()
    activity = ActivityLog(
        event_type='application_created',
        user_id=current_user_id,
        description=f'Created application: {application.name}',
        ip_address=request.remote_addr
    )
    db.session.add(activity)
    db.session.commit()

    return jsonify({
        'message': 'Application created successfully',
        'application': application.to_dict()
    }), 201


@applications_bp.route('/<int:app_id>', methods=['GET'])
@jwt_required()
def get_application(app_id):
    """Get a specific application by ID"""
    application = Application.query.get(app_id)
    if not application:
        return jsonify({
            'error': {
                'code': 'APPLICATION_NOT_FOUND',
                'message': f'Application with id {app_id} not found'
            }
        }), 404

    return jsonify(application.to_dict()), 200


@applications_bp.route('/<int:app_id>', methods=['PUT'])
@jwt_required()
@validate_json_body(ApplicationUpdateSchema)
def update_application(app_id, validated_data: ApplicationUpdateSchema):
    """Update an application"""
    error = require_admin()
    if error:
        return error

    application = Application.query.get(app_id)
    if not application:
        return jsonify({
            'error': {
                'code': 'APPLICATION_NOT_FOUND',
                'message': f'Application with id {app_id} not found'
            }
        }), 404

    # Update fields
    if validated_data.name:
        # Check if new name already exists
        existing = Application.query.filter(
            Application.name == validated_data.name,
            Application.id != app_id
        ).first()
        if existing:
            return jsonify({
                'error': {
                    'code': 'APPLICATION_EXISTS',
                    'message': 'An application with this name already exists'
                }
            }), 409
        application.name = validated_data.name

    if validated_data.description is not None:
        application.description = validated_data.description

    if validated_data.url is not None:
        application.url = str(validated_data.url) if validated_data.url else None

    if validated_data.status:
        application.status = validated_data.status

    db.session.commit()

    # Log activity
    current_user_id = get_jwt_identity()
    activity = ActivityLog(
        event_type='application_updated',
        user_id=current_user_id,
        description=f'Updated application: {application.name}',
        ip_address=request.remote_addr
    )
    db.session.add(activity)
    db.session.commit()

    return jsonify({
        'message': 'Application updated successfully',
        'application': application.to_dict()
    }), 200


@applications_bp.route('/<int:app_id>', methods=['DELETE'])
@jwt_required()
def delete_application(app_id):
    """Delete an application"""
    error = require_admin()
    if error:
        return error

    application = Application.query.get(app_id)
    if not application:
        return jsonify({
            'error': {
                'code': 'APPLICATION_NOT_FOUND',
                'message': f'Application with id {app_id} not found'
            }
        }), 404

    name = application.name
    db.session.delete(application)
    db.session.commit()

    # Log activity
    current_user_id = get_jwt_identity()
    activity = ActivityLog(
        event_type='application_deleted',
        user_id=current_user_id,
        description=f'Deleted application: {name}',
        ip_address=request.remote_addr
    )
    db.session.add(activity)
    db.session.commit()

    return jsonify({
        'message': 'Application deleted successfully'
    }), 200

