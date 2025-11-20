from app.models.base import BaseModel
from datetime import datetime
from typing import Optional


class ActivityLog(BaseModel):
    """ActivityLog model for Firestore"""
    collection_name = 'activity_logs'
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Set defaults
        if 'timestamp' not in self._data:
            self._data['timestamp'] = datetime.utcnow()
    
    def to_dict(self):
        """Convert to dictionary"""
        # Get user email if user_id exists
        user_email = None
        if hasattr(self, 'user_id') and self.user_id:
            from app.models.user import User
            user = User.get_by_id(self.user_id)
            if user:
                user_email = user.email
        
        return {
            'id': self.id,
            'event_type': self.event_type,
            'user_id': self.user_id if hasattr(self, 'user_id') else None,
            'user_email': user_email,
            'description': self.description,
            'ip_address': self.ip_address if hasattr(self, 'ip_address') else None,
            'timestamp': self.timestamp.isoformat() if hasattr(self, 'timestamp') and self.timestamp else None
        }
    
    @classmethod
    def get_recent(cls, limit: int = 50):
        """Get recent activity logs"""
        collection = cls.get_collection()
        # Firestore doesn't support order_by on all fields easily, so we'll get all and sort in memory
        # For better performance, consider using a timestamp index
        docs = collection.order_by('timestamp', direction='DESCENDING').limit(limit).stream()
        return [cls(id=doc.id, **doc.to_dict()) for doc in docs]
    
    @classmethod
    def get_by_date_range(cls, start_date: datetime, end_date: Optional[datetime] = None):
        """Get activity logs within date range"""
        collection = cls.get_collection()
        query = collection.where('timestamp', '>=', start_date)
        if end_date:
            query = query.where('timestamp', '<=', end_date)
        docs = query.stream()
        return [cls(id=doc.id, **doc.to_dict()) for doc in docs]
    
    def __repr__(self):
        return f'<ActivityLog {self.event_type if hasattr(self, "event_type") else "Unknown"} at {self.timestamp if hasattr(self, "timestamp") else "Unknown"}>'
