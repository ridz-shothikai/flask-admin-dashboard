from app import db
from datetime import datetime
import bcrypt

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(
        db.String(20),
        nullable=False,
        default='user'
    )  # superadmin, admin, user
    status = db.Column(
        db.String(20),
        nullable=False,
        default='active'
    )  # active, inactive
    # Profile
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    # Timestamps
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    # Relationships (Many-to-Many with Applications)
    assigned_applications = db.relationship(
        'Application',
        secondary='user_applications',
        back_populates='users'
    )
    # Activity logs
    activities = db.relationship(
        'ActivityLog',
        back_populates='user',
        cascade='all, delete-orphan'
    )

    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

    def check_password(self, password):
        """Verify password"""
        return bcrypt.checkpw(
            password.encode('utf-8'),
            self.password_hash.encode('utf-8')
        )

    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'email': self.email,
            'role': self.role,
            'status': self.status,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'created_date': self.created_date.isoformat() if self.created_date else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'assigned_applications': [app.to_dict() for app in self.assigned_applications]
        }

    def __repr__(self):
        return f'<User {self.email}>'


# Association table for User-Application many-to-many
user_applications = db.Table(
    'user_applications',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('application_id', db.Integer, db.ForeignKey('applications.id'), primary_key=True),
    db.Column('assigned_date', db.DateTime, default=datetime.utcnow)
)
