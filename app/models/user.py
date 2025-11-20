from app.models.base import BaseModel
from app.db import get_db
from datetime import datetime
import bcrypt
from typing import List, Optional


class User(BaseModel):
    """User model for Firestore"""
    collection_name = 'users'
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Set defaults
        if 'role' not in self._data:
            self._data['role'] = 'user'
        if 'status' not in self._data:
            self._data['status'] = 'active'
        if 'created_date' not in self._data:
            self._data['created_date'] = datetime.utcnow()
        if 'assigned_application_ids' not in self._data:
            self._data['assigned_application_ids'] = []
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')
    
    def check_password(self, password):
        """Verify password"""
        if not hasattr(self, 'password_hash') or not self.password_hash:
            return False
        return bcrypt.checkpw(
            password.encode('utf-8'),
            self.password_hash.encode('utf-8')
        )
    
    def to_dict(self):
        """Convert to dictionary"""
        result = {
            'id': self.id,
            'email': self.email,
            'role': self.role,
            'status': self.status,
            'first_name': self.first_name if hasattr(self, 'first_name') else None,
            'last_name': self.last_name if hasattr(self, 'last_name') else None,
            'created_date': self.created_date.isoformat() if hasattr(self, 'created_date') and self.created_date else None,
            'last_login': self.last_login.isoformat() if hasattr(self, 'last_login') and self.last_login else None,
        }
        
        # Load assigned applications if needed
        if hasattr(self, 'assigned_application_ids') and self.assigned_application_ids:
            from app.models.application import Application
            apps = []
            for app_id in self.assigned_application_ids:
                app = Application.get_by_id(app_id)
                if app:
                    apps.append(app.to_dict())
            result['assigned_applications'] = apps
        else:
            result['assigned_applications'] = []
        
        return result
    
    @classmethod
    def get_by_email(cls, email: str):
        """Get user by email"""
        users = cls.query(email=email)
        return users[0] if users else None
    
    @classmethod
    def email_exists(cls, email: str, exclude_id: Optional[str] = None) -> bool:
        """Check if email already exists"""
        users = cls.query(email=email)
        if exclude_id:
            users = [u for u in users if u.id != exclude_id]
        return len(users) > 0
    
    def get_assigned_applications(self):
        """Get assigned applications"""
        if not hasattr(self, 'assigned_application_ids') or not self.assigned_application_ids:
            return []
        
        from app.models.application import Application
        apps = []
        for app_id in self.assigned_application_ids:
            app = Application.get_by_id(app_id)
            if app:
                apps.append(app)
        return apps
    
    def assign_application(self, application_id: str):
        """Assign an application to user"""
        if not hasattr(self, 'assigned_application_ids'):
            self.assigned_application_ids = []
        if application_id not in self.assigned_application_ids:
            self.assigned_application_ids.append(application_id)
    
    def unassign_application(self, application_id: str):
        """Unassign an application from user"""
        if hasattr(self, 'assigned_application_ids') and application_id in self.assigned_application_ids:
            self.assigned_application_ids.remove(application_id)
    
    def __repr__(self):
        return f'<User {self.email if hasattr(self, "email") else "Unknown"}>'


def get_user_applications(user_id: str) -> List[dict]:
    """Get user-application relationships"""
    db = get_db()
    relationships = db.collection('user_applications').where('user_id', '==', user_id).stream()
    return [{'id': doc.id, **doc.to_dict()} for doc in relationships]


def create_user_application(user_id: str, application_id: str):
    """Create user-application relationship"""
    db = get_db()
    db.collection('user_applications').add({
        'user_id': user_id,
        'application_id': application_id,
        'assigned_date': datetime.utcnow()
    })


def delete_user_application(user_id: str, application_id: str):
    """Delete user-application relationship"""
    db = get_db()
    relationships = db.collection('user_applications').where('user_id', '==', user_id).where('application_id', '==', application_id).stream()
    for doc in relationships:
        doc.reference.delete()
