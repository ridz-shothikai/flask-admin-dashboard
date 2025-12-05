from app.models.base import BaseModel
from datetime import datetime
from typing import Optional


class FileCategory(BaseModel):
    """FileCategory model for Firestore"""
    collection_name = 'file_categories'
    
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
            'code': self.code,
            'name': self.name if hasattr(self, 'name') else self.code,
            'description': self.description if hasattr(self, 'description') else None,
            'status': self.status,
            'created_date': self.created_date.isoformat() if hasattr(self, 'created_date') and self.created_date else None,
            'last_updated': self.last_updated.isoformat() if hasattr(self, 'last_updated') and self.last_updated else None,
            'user_count': user_count
        }
    
    @classmethod
    def get_by_code(cls, code: str):
        """Get file category by code"""
        categories = cls.query(code=code)
        return categories[0] if categories else None
    
    @classmethod
    def code_exists(cls, code: str, exclude_id: Optional[str] = None) -> bool:
        """Check if code already exists"""
        categories = cls.query(code=code)
        if exclude_id:
            categories = [c for c in categories if c.id != exclude_id]
        return len(categories) > 0
    
    def get_user_count(self) -> int:
        """Get count of users assigned to this category"""
        from app.models.user import User
        all_users = User.get_all()
        count = 0
        for user in all_users:
            if hasattr(user, 'assigned_file_category_ids') and user.assigned_file_category_ids:
                if self.id in user.assigned_file_category_ids:
                    count += 1
        return count
    
    def save(self) -> str:
        """Override save to update last_updated"""
        self.last_updated = datetime.utcnow()
        return super().save()
    
    def __repr__(self):
        return f'<FileCategory {self.code if hasattr(self, "code") else "Unknown"}>'

    @classmethod
    def delete_all(cls) -> int:
        """Delete ALL file categories (dangerous)"""
        docs = cls.get_all()
        for doc in docs:
            doc.delete()
        return len(docs)