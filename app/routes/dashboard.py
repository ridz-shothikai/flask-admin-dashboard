from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required
from sqlalchemy import func
from datetime import datetime, timedelta
from app import db
from app.models import User, Application, ActivityLog, SystemMetric
from app.utils.monitoring import get_system_health

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/api/dashboard')


@dashboard_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_stats():
    """Get dashboard statistics"""
    # User counts
    total_users = User.query.count()
    active_users = User.query.filter_by(status='active').count()
    inactive_users = User.query.filter_by(status='inactive').count()

    # Users by role
    users_by_role = db.session.query(
        User.role,
        func.count(User.id)
    ).group_by(User.role).all()
    role_counts = {role: count for role, count in users_by_role}

    # Application counts
    total_applications = Application.query.count()
    active_applications = Application.query.filter_by(status='active').count()

    # Recent activity count (last 24 hours)
    yesterday = datetime.utcnow() - timedelta(days=1)
    recent_activities = ActivityLog.query.filter(
        ActivityLog.timestamp >= yesterday
    ).count()

    # Recent logins (last 7 days)
    week_ago = datetime.utcnow() - timedelta(days=7)
    recent_logins = User.query.filter(
        User.last_login >= week_ago
    ).count()

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
            'recent_count': recent_activities
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
    activities = ActivityLog.query.order_by(
        ActivityLog.timestamp.desc()
    ).limit(50).all()

    return jsonify({
        'activities': [activity.to_dict() for activity in activities]
    }), 200


@dashboard_bp.route('/metrics/history', methods=['GET'])
@jwt_required()
def get_metrics_history():
    """Get historical system metrics (last 24 hours)"""
    yesterday = datetime.utcnow() - timedelta(days=1)
    metrics = SystemMetric.query.filter(
        SystemMetric.timestamp >= yesterday
    ).order_by(SystemMetric.timestamp.asc()).all()

    return jsonify({
        'metrics': [metric.to_dict() for metric in metrics]
    }), 200

