from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator
from typing import Optional, List, Literal
from datetime import datetime


class LoginSchema(BaseModel):
    """Login request schema"""
    email: EmailStr
    password: str = Field(..., min_length=6)


class LastRegionSchema(BaseModel):
    """Schema for saving last used region"""
    application_id: str = Field(..., description="ID of the last used region application")


class PasswordChangeSchema(BaseModel):
    """Password change request schema"""
    current_password: str = Field(..., min_length=1, description="Current password")
    new_password: str = Field(..., min_length=6, description="New password")
    
    @field_validator('new_password')
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Validate password strength"""
        if len(v) < 6:
            raise ValueError('New password must be at least 6 characters')
        return v


class LastAccessedRegionSchema(BaseModel):
    """Last accessed region update schema"""
    last_accessed_region: Optional[str] = None


class InitSuperuserSchema(BaseModel):
    """Superuser initialization schema (same as UserCreateSchema but without application_ids and file_category_ids)"""
    email: EmailStr
    password: str = Field(..., min_length=6)
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    
    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Validate password strength"""
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters')
        return v



class FileManagementPermissionsSchema(BaseModel):
    """File management permissions schema"""
    can_rename_source: bool = False
    can_delete_source: bool = False
    can_upload: bool = False
    can_create_root_folder_source: bool = False
    can_create_folder_source: bool = False
    can_delete_destination: bool = False
    can_create_root_folder_destination: bool = False
    can_create_folder_destination: bool = False
    can_transfer: bool = True
    can_view_all_transfer_history: bool = False


class AdminPanelAccessPermissionSchema(BaseModel):
    """Admin panel access permissions schema"""
    can_access_regions: bool = False
    can_manage_users: bool = False
    can_manage_roles: bool = False
    can_update_settings: bool = False


class UserCreateSchema(BaseModel):
    """User creation schema"""
    email: EmailStr
    password: str = Field(..., min_length=6)
    role: Literal['superadmin', 'superuser', 'manager', 'supervisor', 'staff'] = 'staff'
    status: Literal['active', 'inactive'] = 'active'
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    last_accessed_region: Optional[str] = None
    application_ids: List[str] = Field(default_factory=list, description="List of application IDs (strings)")
    file_category_ids: List[str] = Field(default_factory=list, description="List of file category IDs (strings)")
    file_management_permissions: Optional[FileManagementPermissionsSchema] = None
    admin_panel_access_permission: Optional[AdminPanelAccessPermissionSchema] = None
    
    @field_validator('application_ids', mode='before')
    @classmethod
    def validate_application_ids(cls, v):
        """Ensure application_ids are strings, not integers"""
        if v is None:
            return []
        if isinstance(v, list):
            # Convert all items to strings explicitly
            return [str(item) for item in v]
        return v

    @field_validator('file_category_ids', mode='before')
    @classmethod
    def validate_file_category_ids(cls, v):
        """Ensure file_category_ids are strings, not integers"""
        if v is None:
            return []
        if isinstance(v, list):
            # Convert all items to strings explicitly
            return [str(item) for item in v]
        return v

    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Validate password strength"""
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters')
        return v


class UserUpdateSchema(BaseModel):
    """User update schema - all fields optional"""
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=6)
    role: Optional[Literal['superadmin', 'superuser', 'manager', 'supervisor', 'staff']] = None
    status: Optional[Literal['active', 'inactive']] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    last_accessed_region: Optional[str] = None
    application_ids: Optional[List[str]] = None
    file_category_ids: Optional[List[str]] = None
    file_management_permissions: Optional[FileManagementPermissionsSchema] = None
    admin_panel_access_permission: Optional[AdminPanelAccessPermissionSchema] = None
    
    @field_validator('application_ids', mode='before')
    @classmethod
    def validate_application_ids(cls, v):
        """Ensure application_ids are strings, not integers"""
        if v is None:
            return None
        if isinstance(v, list):
            # Convert all items to strings explicitly
            return [str(item) for item in v]
        return v

    @field_validator('file_category_ids', mode='before')
    @classmethod
    def validate_file_category_ids(cls, v):
        """Ensure file_category_ids are strings, not integers"""
        if v is None:
            return None
        if isinstance(v, list):
            # Convert all items to strings explicitly
            return [str(item) for item in v]
        return v

    @model_validator(mode='after')
    def check_at_least_one_field(self):
        """Ensure at least one field is provided"""
        if not any([
            self.email is not None,
            self.password is not None,
            self.role is not None,
            self.status is not None,
            self.first_name is not None,
            self.last_name is not None,
            self.last_accessed_region is not None,
            self.application_ids is not None,
            self.file_category_ids is not None,
            self.file_management_permissions is not None,
            self.admin_panel_access_permission is not None,
        ]):
            raise ValueError('At least one field must be provided for update')
        return self


class UserQuerySchema(BaseModel):
    """User query parameters schema"""
    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=20, ge=1, le=100)
    search: Optional[str] = None
    role: Optional[Literal['user', 'admin', 'superadmin', 'manager', 'clark']] = None
    status: Optional[Literal['active', 'inactive']] = None
    category: Optional[List[str]] = None
    sort: str = 'created_date'
    order: Literal['asc', 'desc'] = 'desc'
    
    @field_validator('category', mode='before')
    @classmethod
    def validate_category(cls, v):
        """Ensure category IDs are strings, not integers"""
        if v is None:
            return None
        if isinstance(v, list):
            # Filter out empty strings and convert all items to strings
            return [str(item) for item in v if item and str(item).strip()]
        # Handle single value case (convert to list)
        if isinstance(v, str) and v.strip():
            return [str(v)]
        return None
    
    model_config = {
        'extra': 'forbid'  # Forbid extra fields
    }


class UserResponseSchema(BaseModel):
    """User response schema"""
    id: str
    email: str
    role: str
    status: str
    first_name: Optional[str]
    last_name: Optional[str]
    created_date: Optional[datetime]
    last_login: Optional[datetime]
    last_accessed_region: Optional[str]
    assigned_applications: List[dict]
    assigned_file_categories: Optional[List[dict]] = None
    file_management_permissions: Optional[dict] = None
    admin_panel_access_permission: Optional[dict] = None
    model_config = {
        'from_attributes': True  # Allow ORM models
    }

