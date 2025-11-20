"""
Base model class for Firestore documents
"""
from datetime import datetime
from typing import Optional, Dict, Any
from app.db import get_db


class BaseModel:
    """Base model for Firestore documents"""
    collection_name: str = None
    
    def __init__(self, **kwargs):
        """Initialize model with data"""
        self.id = kwargs.get('id')
        self._data = {k: v for k, v in kwargs.items() if k != 'id'}
    
    @classmethod
    def get_collection(cls):
        """Get Firestore collection reference"""
        if not cls.collection_name:
            raise ValueError(f"collection_name not set for {cls.__name__}")
        return get_db().collection(cls.collection_name)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary"""
        result = {'id': self.id} if self.id else {}
        result.update(self._data)
        return result
    
    def save(self) -> str:
        """Save document to Firestore"""
        collection = self.get_collection()
        # Convert datetime objects to Firestore timestamps
        data = self._prepare_data_for_firestore(self._data)
        
        if self.id:
            # Update existing document
            doc_ref = collection.document(self.id)
            doc_ref.update(data)
            return self.id
        else:
            # Create new document
            # collection.add() returns (timestamp, DocumentReference)
            _, doc_ref = collection.add(data)
            self.id = doc_ref.id
            return self.id
    
    def delete(self):
        """Delete document from Firestore"""
        if not self.id:
            raise ValueError("Cannot delete document without id")
        collection = self.get_collection()
        collection.document(self.id).delete()
    
    @classmethod
    def get_by_id(cls, doc_id: str):
        """Get document by ID"""
        doc = cls.get_collection().document(doc_id).get()
        if doc.exists:
            data = doc.to_dict()
            data['id'] = doc.id
            return cls(**data)
        return None
    
    @classmethod
    def get_all(cls, limit: Optional[int] = None):
        """Get all documents"""
        query = cls.get_collection()
        if limit:
            query = query.limit(limit)
        docs = query.stream()
        return [cls(id=doc.id, **doc.to_dict()) for doc in docs]
    
    @classmethod
    def query(cls, **filters):
        """Query documents with filters"""
        query = cls.get_collection()
        for field, value in filters.items():
            query = query.where(field, '==', value)
        docs = query.stream()
        return [cls(id=doc.id, **doc.to_dict()) for doc in docs]
    
    @classmethod
    def count(cls, **filters) -> int:
        """Count documents matching filters"""
        query = cls.get_collection()
        for field, value in filters.items():
            query = query.where(field, '==', value)
        return len(list(query.stream()))
    
    def _prepare_data_for_firestore(self, data: Dict) -> Dict:
        """Prepare data for Firestore (convert datetime, etc.)"""
        result = {}
        for key, value in data.items():
            if isinstance(value, datetime):
                result[key] = value
            elif value is not None:
                result[key] = value
        return result
    
    def __getattr__(self, name):
        """Get attribute from _data"""
        if name in self._data:
            return self._data[name]
        raise AttributeError(f"{self.__class__.__name__} has no attribute '{name}'")
    
    def __setattr__(self, name, value):
        """Set attribute in _data"""
        if name in ['id', '_data']:
            super().__setattr__(name, value)
        else:
            if not hasattr(self, '_data'):
                super().__setattr__('_data', {})
            self._data[name] = value

