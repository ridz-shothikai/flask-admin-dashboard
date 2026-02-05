from app.models.base import BaseModel
from datetime import datetime
from typing import Optional


class Application(BaseModel):
    """Application model for Firestore"""
    collection_name = 'applications'
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Set defaults
        if 'status' not in self._data:
            self._data['status'] = 'active'
        if 'created_date' not in self._data:
            self._data['created_date'] = datetime.utcnow()
        if 'last_updated' not in self._data:
            self._data['last_updated'] = datetime.utcnow()
    
    def to_dict(self, user_count=None):
        """Convert to dictionary with optional pre-calculated user_count for performance"""
        # Use provided user_count or calculate it if not provided (for backward compatibility)
        if user_count is None:
            user_count = self.get_user_count()
        
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description if hasattr(self, 'description') else None,
            'url': self.url if hasattr(self, 'url') else None,
            'status': self.status,
            'created_date': self.created_date.isoformat() if hasattr(self, 'created_date') and self.created_date else None,
            'last_updated': self.last_updated.isoformat() if hasattr(self, 'last_updated') and self.last_updated else None,
            'user_count': user_count
        }
    
    @classmethod
    def get_by_name(cls, name: str):
        """Get application by name"""
        apps = cls.query(name=name)
        return apps[0] if apps else None
    
    @classmethod
    def name_exists(cls, name: str, exclude_id: Optional[str] = None) -> bool:
        """Check if name already exists"""
        apps = cls.query(name=name)
        if exclude_id:
            apps = [a for a in apps if a.id != exclude_id]
        return len(apps) > 0
    
    def get_user_count(self) -> int:
        """Get count of users assigned to this application"""
        from app.db import get_db
        db = get_db()
        # Query users where assigned_application_ids array contains this application ID
        users = db.collection('users').where('assigned_application_ids', 'array_contains', self.id).stream()
        return len(list(users))
    
    def save(self) -> str:
        """Override save to update last_updated"""
        self.last_updated = datetime.utcnow()
        return super().save()
    
    def __repr__(self):
        return f'<Application {self.name if hasattr(self, "name") else "Unknown"}>'
