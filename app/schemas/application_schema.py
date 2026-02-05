from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, Literal
from datetime import datetime


class ApplicationCreateSchema(BaseModel):
    """Application creation schema"""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    url: Optional[HttpUrl] = None
    status: Literal['active', 'inactive', 'maintenance'] = 'active'


class ApplicationUpdateSchema(BaseModel):
    """Application update schema"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    url: Optional[HttpUrl] = None
    status: Optional[Literal['active', 'inactive', 'maintenance']] = None


class ApplicationQuerySchema(BaseModel):
    """Application query parameters schema"""
    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=20, ge=1, le=100)
    search: Optional[str] = None
    status: Optional[Literal['active', 'inactive', 'maintenance']] = None
    sort: str = 'name'
    order: Literal['asc', 'desc'] = 'asc'
    model_config = {
        'extra': 'forbid'
    }


class ApplicationResponseSchema(BaseModel):
    """Application response schema"""
    id: str
    name: str
    description: Optional[str]
    url: Optional[str]
    status: str
    created_date: Optional[datetime]
    last_updated: Optional[datetime]
    user_count: int
    model_config = {
        'from_attributes': True
    }

