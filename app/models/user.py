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
            self._data['role'] = 'staff'
        if 'status' not in self._data:
            self._data['status'] = 'active'
        if 'created_date' not in self._data:
            self._data['created_date'] = datetime.utcnow()
        if 'assigned_application_ids' not in self._data:
            self._data['assigned_application_ids'] = []
        if 'assigned_file_category_ids' not in self._data:
            self._data['assigned_file_category_ids'] = []
        if 'file_management_permissions' not in self._data:
            self._data['file_management_permissions'] = {
                'can_rename_source': False,
                'can_delete_source': False,
                'can_upload': False,
                'can_create_root_folder_source': False,
                'can_create_folder_source': False,
                'can_delete_destination': False,
                'can_create_root_folder_destination': False,
                'can_create_folder_destination': False,
                'can_transfer': True,
                'can_view_all_transfer_history': False
            }
    
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
    
    def to_dict(self, applications_cache=None, file_categories_cache=None, 
                app_user_counts=None, category_user_counts=None):
        """Convert to dictionary with optional pre-loaded caches for performance"""
        result = {
            'id': self.id,
            'email': self.email,
            'role': self.role,
            'status': self.status,
            'first_name': self.first_name if hasattr(self, 'first_name') else None,
            'last_name': self.last_name if hasattr(self, 'last_name') else None,
            'created_date': self.created_date.isoformat() if hasattr(self, 'created_date') and self.created_date else None,
            'last_login': self.last_login.isoformat() if hasattr(self, 'last_login') and self.last_login else None,
            'file_management_permissions': self.file_management_permissions if hasattr(self, 'file_management_permissions') else None,
        }
        
        # Load assigned applications if needed
        if hasattr(self, 'assigned_application_ids') and self.assigned_application_ids:
            from app.models.application import Application
            apps = []
            if applications_cache is not None:
                # Use pre-loaded cache for O(1) lookup
                for app_id in self.assigned_application_ids:
                    app = applications_cache.get(app_id)
                    if app:
                        # Get user_count from provided counts if available
                        app_user_count = app_user_counts.get(app_id) if app_user_counts else None
                        apps.append(app.to_dict(user_count=app_user_count))
            else:
                # Fallback to individual queries (for backward compatibility)
                for app_id in self.assigned_application_ids:
                    app = Application.get_by_id(app_id)
                    if app:
                        apps.append(app.to_dict())
            result['assigned_applications'] = apps
        else:
            result['assigned_applications'] = []
        
        # Load assigned file categories if needed
        if hasattr(self, 'assigned_file_category_ids') and self.assigned_file_category_ids:
            from app.models.file_category import FileCategory
            categories = []
            if file_categories_cache is not None:
                # Use pre-loaded cache for O(1) lookup
                for category_id in self.assigned_file_category_ids:
                    category = file_categories_cache.get(category_id)
                    if category:
                        # Get user_count from provided counts if available
                        cat_user_count = category_user_counts.get(category_id) if category_user_counts else None
                        categories.append(category.to_dict(user_count=cat_user_count))
            else:
                # Fallback to individual queries (for backward compatibility)
                for category_id in self.assigned_file_category_ids:
                    category = FileCategory.get_by_id(category_id)
                    if category:
                        categories.append(category.to_dict())
            result['assigned_file_categories'] = categories
        else:
            result['assigned_file_categories'] = []
        
        return result
    
    def to_dict_simple(self):
        """Convert to dictionary without user counts for assigned_applications and assigned_file_categories (optimized for login API)"""
        result = {
            'id': self.id,
            'email': self.email,
            'role': self.role,
            'status': self.status,
            'first_name': self.first_name if hasattr(self, 'first_name') else None,
            'last_name': self.last_name if hasattr(self, 'last_name') else None,
            'created_date': self.created_date.isoformat() if hasattr(self, 'created_date') and self.created_date else None,
            'last_login': self.last_login.isoformat() if hasattr(self, 'last_login') and self.last_login else None,
            'file_management_permissions': self.file_management_permissions if hasattr(self, 'file_management_permissions') else None,
        }
        
        # Import once for both applications and file categories
        from app.db import get_db
        db = get_db()
        
        # Batch load assigned applications - convert directly to dict without creating objects
        if hasattr(self, 'assigned_application_ids') and self.assigned_application_ids:
            # Batch load all applications in a single Firestore request
            app_refs = [db.collection('applications').document(app_id) for app_id in self.assigned_application_ids]
            apps = []
            if app_refs:
                docs = db.get_all(app_refs)
                for doc in docs:
                    if doc.exists:
                        data = doc.to_dict()
                        # Convert directly to dict - skip Application object creation
                        app_dict = {
                            'id': doc.id,
                            'name': data.get('name'),
                            'description': data.get('description'),
                            'url': data.get('url'),
                            'status': data.get('status', 'active'),
                            'created_date': data.get('created_date').isoformat() if data.get('created_date') else None,
                            'last_updated': data.get('last_updated').isoformat() if data.get('last_updated') else None,
                        }
                        apps.append(app_dict)
            result['assigned_applications'] = apps
        else:
            result['assigned_applications'] = []
        
        # Batch load assigned file categories - convert directly to dict without creating objects
        if hasattr(self, 'assigned_file_category_ids') and self.assigned_file_category_ids:
            # Batch load all file categories in a single Firestore request
            category_refs = [db.collection('file_categories').document(cat_id) for cat_id in self.assigned_file_category_ids]
            categories = []
            if category_refs:
                docs = db.get_all(category_refs)
                for doc in docs:
                    if doc.exists:
                        data = doc.to_dict()
                        # Convert directly to dict - skip FileCategory object creation
                        category_dict = {
                            'id': doc.id,
                            'code': data.get('code'),
                            'name': data.get('name') or data.get('code'),
                            'description': data.get('description'),
                            'status': data.get('status', 'active'),
                            'short_code': data.get('short_code', []),
                            'created_date': data.get('created_date').isoformat() if data.get('created_date') else None,
                            'last_updated': data.get('last_updated').isoformat() if data.get('last_updated') else None,
                        }
                        categories.append(category_dict)
            result['assigned_file_categories'] = categories
        else:
            result['assigned_file_categories'] = []
        
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
