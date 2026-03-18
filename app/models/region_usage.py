from app.models.base import BaseModel
from datetime import datetime

class RegionUsage(BaseModel):
    """RegionUsage model for Firestore to track last accessed region per user"""
    collection_name = 'region_usage'
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Set defaults
        if 'last_accessed' not in self._data:
            self._data['last_accessed'] = datetime.utcnow()

    @classmethod
    def get_by_user_id(cls, user_id: str):
        """Get the last region usage for a user"""
        # Since we only want the LAST one, we should ideally query and sort,
        # but for this requirement, we can just maintain ONE document per user.
        results = cls.query(user_id=user_id)
        return results[0] if results else None

    def save(self) -> str:
        """Override save to update last_accessed"""
        self.last_accessed = datetime.utcnow()
        return super().save()

    def __repr__(self):
        return f'<RegionUsage user:{self.user_id} app:{self.application_id}>'
