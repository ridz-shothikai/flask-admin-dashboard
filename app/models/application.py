from app import db
from datetime import datetime


class Application(db.Model):
    __tablename__ = 'applications'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False, index=True)
    description = db.Column(db.Text)
    url = db.Column(db.String(255))
    status = db.Column(
        db.String(20),
        nullable=False,
        default='active'
    )  # active, inactive, maintenance
    # Timestamps
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    # Relationships
    users = db.relationship(
        'User',
        secondary='user_applications',
        back_populates='assigned_applications'
    )

    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'url': self.url,
            'status': self.status,
            'created_date': self.created_date.isoformat() if self.created_date else None,
            'last_updated': self.last_updated.isoformat() if self.last_updated else None,
            'user_count': len(self.users)
        }

    def __repr__(self):
        return f'<Application {self.name}>'
