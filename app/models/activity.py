from app import db
from datetime import datetime


class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(50), nullable=False, index=True)
    # user_login, user_logout, user_created, user_updated, user_deleted,
    # app_created, app_updated, app_deleted, etc.
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    description = db.Column(db.Text, nullable=False)
    ip_address = db.Column(db.String(45))  # IPv6 compatible
    user_agent = db.Column(db.String(255))
    # Additional context (JSON-like storage)
    extra_metadata = db.Column(db.Text)  # Can store JSON string (renamed from 'metadata' - reserved by SQLAlchemy)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    # Relationships
    user = db.relationship('User', back_populates='activities')

    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'event_type': self.event_type,
            'user_id': self.user_id,
            'user_email': self.user.email if self.user else None,
            'description': self.description,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }

    def __repr__(self):
        return f'<ActivityLog {self.event_type} at {self.timestamp}>'

