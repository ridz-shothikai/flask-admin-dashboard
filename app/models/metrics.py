from app.models.base import BaseModel
from datetime import datetime
from typing import Optional


class SystemMetric(BaseModel):
    """SystemMetric model for Firestore"""
    collection_name = 'system_metrics'
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Set defaults
        if 'timestamp' not in self._data:
            self._data['timestamp'] = datetime.utcnow()
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'cpu_usage': round(self.cpu_usage, 2) if hasattr(self, 'cpu_usage') and self.cpu_usage else None,
            'memory_usage': round(self.memory_usage, 2) if hasattr(self, 'memory_usage') and self.memory_usage else None,
            'memory_total': self.memory_total if hasattr(self, 'memory_total') else None,
            'memory_used': self.memory_used if hasattr(self, 'memory_used') else None,
            'disk_usage': round(self.disk_usage, 2) if hasattr(self, 'disk_usage') and self.disk_usage else None,
            'disk_total': self.disk_total if hasattr(self, 'disk_total') else None,
            'disk_used': self.disk_used if hasattr(self, 'disk_used') else None,
            'timestamp': self.timestamp.isoformat() if hasattr(self, 'timestamp') and self.timestamp else None
        }
    
    @classmethod
    def get_by_date_range(cls, start_date: datetime, end_date: Optional[datetime] = None):
        """Get metrics within date range"""
        collection = cls.get_collection()
        query = collection.where('timestamp', '>=', start_date)
        if end_date:
            query = query.where('timestamp', '<=', end_date)
        query = query.order_by('timestamp')
        docs = query.stream()
        return [cls(id=doc.id, **doc.to_dict()) for doc in docs]
    
    def __repr__(self):
        return f'<SystemMetric at {self.timestamp if hasattr(self, "timestamp") else "Unknown"}>'
