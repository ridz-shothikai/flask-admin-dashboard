from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator
from typing import Optional, List, Literal
from datetime import datetime


class LoginSchema(BaseModel):
    """Login request schema"""
    email: EmailStr
    password: str = Field(..., min_length=6)


class UserCreateSchema(BaseModel):
    """User creation schema"""
    email: EmailStr
    password: str = Field(..., min_length=6)
    role: Literal['user', 'admin', 'superadmin'] = 'user'
    status: Literal['active', 'inactive'] = 'active'
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    application_ids: List[int] = Field(default_factory=list)

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
    role: Optional[Literal['user', 'admin', 'superadmin']] = None
    status: Optional[Literal['active', 'inactive']] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    application_ids: Optional[List[int]] = None

    @model_validator(mode='after')
    def check_at_least_one_field(self):
        """Ensure at least one field is provided"""
        if not any([
            self.email, self.password, self.role, self.status,
            self.first_name, self.last_name, self.application_ids
        ]):
            raise ValueError('At least one field must be provided for update')
        return self


class UserQuerySchema(BaseModel):
    """User query parameters schema"""
    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=20, ge=1, le=100)
    search: Optional[str] = None
    role: Optional[Literal['user', 'admin', 'superadmin']] = None
    status: Optional[Literal['active', 'inactive']] = None
    sort: str = 'created_date'
    order: Literal['asc', 'desc'] = 'desc'
    model_config = {
        'extra': 'forbid'  # Forbid extra fields
    }


class UserResponseSchema(BaseModel):
    """User response schema"""
    id: int
    email: str
    role: str
    status: str
    first_name: Optional[str]
    last_name: Optional[str]
    created_date: Optional[datetime]
    last_login: Optional[datetime]
    assigned_applications: List[dict]
    model_config = {
        'from_attributes': True  # Allow ORM models
    }

