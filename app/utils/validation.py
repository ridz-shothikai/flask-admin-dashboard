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
                    data = request.args.to_dict()
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
                return jsonify({
                    'error': {
                        'code': 'VALIDATION_ERROR',
                        'message': 'Invalid input data',
                        'details': e.errors()
                    }
                }), 400
            except Exception as e:
                return jsonify({
                    'error': {
                        'code': 'INTERNAL_ERROR',
                        'message': str(e)
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

