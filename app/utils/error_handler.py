from flask import jsonify
from pydantic import ValidationError


def register_error_handlers(app):
    """Register error handlers for the application"""
    @app.errorhandler(ValidationError)
    def handle_pydantic_validation_error(error):
        """Handle Pydantic validation errors"""
        return jsonify({
            'error': {
                'code': 'VALIDATION_ERROR',
                'message': 'Invalid input data',
                'details': error.errors()
            }
        }), 400

    @app.errorhandler(404)
    def handle_not_found(error):
        return jsonify({
            'error': {
                'code': 'NOT_FOUND',
                'message': 'Resource not found'
            }
        }), 404

    @app.errorhandler(401)
    def handle_unauthorized(error):
        return jsonify({
            'error': {
                'code': 'UNAUTHORIZED',
                'message': 'Authentication required'
            }
        }), 401

    @app.errorhandler(403)
    def handle_forbidden(error):
        return jsonify({
            'error': {
                'code': 'FORBIDDEN',
                'message': 'You do not have permission to access this resource'
            }
        }), 403

    @app.errorhandler(500)
    def handle_internal_error(error):
        return jsonify({
            'error': {
                'code': 'INTERNAL_SERVER_ERROR',
                'message': 'An internal server error occurred'
            }
        }), 500

