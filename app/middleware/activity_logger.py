from flask import request, g
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from functools import wraps
from app import db
from app.models import ActivityLog


def log_activity(event_type, description):
    """Log an activity to the database"""
    try:
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()
    except:
        user_id = None

    activity = ActivityLog(
        event_type=event_type,
        user_id=user_id,
        description=description,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
    db.session.add(activity)
    db.session.commit()
    return activity


def activity_required(event_type):
    """Decorator to automatically log activity for a route"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Execute the function first
            result = f(*args, **kwargs)
            # Log activity after successful execution
            try:
                description = f"Executed {f.__name__}"
                log_activity(event_type, description)
            except:
                pass  # Don't fail the request if logging fails
            return result
        return decorated_function
    return decorator

