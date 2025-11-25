from pydantic import BaseModel, ValidationError
from flask import jsonify, request
from functools import wraps
from typing import Type


def validate_request(schema: Type[BaseModel], source: str = 'json'):
    """
    Decorator to validate Flask request data with Pydantic
    Args:
        schema: Pydantic model class to validate against
        source: Where to get data from ('json', 'args', 'form')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Get data based on source
                if source == 'json':
                    data = request.get_json() or {}
                elif source == 'args':
                    # Convert MultiDict to dict, preserving lists for fields that might be lists
                    data = {}
                    for key in request.args:
                        # Check if key appears multiple times (list parameter)
                        values = request.args.getlist(key)
                        if len(values) > 1:
                            data[key] = values
                        else:
                            data[key] = values[0] if values else None
                elif source == 'form':
                    data = request.form.to_dict()
                else:
                    return jsonify({
                        'error': {
                            'code': 'INVALID_SOURCE',
                            'message': f'Invalid data source: {source}'
                        }
                    }), 500
                # Validate with Pydantic
                validated_data = schema(**data)
                # Add validated data to kwargs
                kwargs['validated_data'] = validated_data
                return f(*args, **kwargs)
            except ValidationError as e:
                # Convert Pydantic errors to JSON-serializable format
                error_details = []
                for error in e.errors():
                    error_details.append({
                        'field': error.get('loc', []),
                        'message': str(error.get('msg', '')),
                        'type': str(error.get('type', ''))
                    })
                return jsonify({
                    'error': {
                        'code': 'VALIDATION_ERROR',
                        'message': 'Invalid input data',
                        'details': error_details
                    }
                }), 400
            except Exception as e:
                # Ensure error message is JSON-serializable
                error_message = str(e) if e else 'An unexpected error occurred'
                return jsonify({
                    'error': {
                        'code': 'INTERNAL_ERROR',
                        'message': error_message
                    }
                }), 500
        return decorated_function
    return decorator


def validate_query_params(schema: Type[BaseModel]):
    """Shorthand for validating query parameters"""
    return validate_request(schema, source='args')


def validate_json_body(schema: Type[BaseModel]):
    """Shorthand for validating JSON body"""
    return validate_request(schema, source='json')

