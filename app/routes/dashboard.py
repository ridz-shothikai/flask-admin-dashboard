from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required
from datetime import datetime, timedelta
from app.models import User, Application, ActivityLog, SystemMetric
from app.utils.monitoring import get_system_health

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/api/dashboard')


@dashboard_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_stats():
    """Get dashboard statistics"""
    # User counts
    all_users = User.get_all()
    total_users = len(all_users)
    active_users = len([u for u in all_users if hasattr(u, 'status') and u.status == 'active'])
    inactive_users = len([u for u in all_users if hasattr(u, 'status') and u.status == 'inactive'])
    
    # Users by role
    role_counts = {}
    for user in all_users:
        if hasattr(user, 'role'):
            role = user.role
            role_counts[role] = role_counts.get(role, 0) + 1
    
    # Application counts
    all_apps = Application.get_all()
    total_applications = len(all_apps)
    active_applications = len([app for app in all_apps if hasattr(app, 'status') and app.status == 'active'])
    
    # Recent activity count (last 24 hours)
    yesterday = datetime.utcnow() - timedelta(days=1)
    recent_activities = ActivityLog.get_by_date_range(yesterday)
    recent_activity_count = len(recent_activities)
    
    # Recent logins (last 7 days)
    week_ago = datetime.utcnow() - timedelta(days=7)
    recent_logins = len([
        u for u in all_users
        if hasattr(u, 'last_login') and u.last_login and u.last_login >= week_ago
    ])

    return jsonify({
        'users': {
            'total': total_users,
            'active': active_users,
            'inactive': inactive_users,
            'by_role': role_counts,
            'recent_logins': recent_logins
        },
        'applications': {
            'total': total_applications,
            'active': active_applications
        },
        'activity': {
            'recent_count': recent_activity_count
        }
    }), 200


@dashboard_bp.route('/health', methods=['GET'])
@jwt_required()
def get_health():
    """Get real-time system health metrics"""
    health = get_system_health()
    return jsonify(health), 200


@dashboard_bp.route('/activity', methods=['GET'])
@jwt_required()
def get_activity():
    """Get recent activity logs"""
    # Get last 50 activities
    activities = ActivityLog.get_recent(limit=50)

    return jsonify({
        'activities': [activity.to_dict() for activity in activities]
    }), 200


@dashboard_bp.route('/metrics/history', methods=['GET'])
@jwt_required()
def get_metrics_history():
    """Get historical system metrics (last 24 hours)"""
    yesterday = datetime.utcnow() - timedelta(days=1)
    metrics = SystemMetric.get_by_date_range(yesterday)

    return jsonify({
        'metrics': [metric.to_dict() for metric in metrics]
    }), 200
