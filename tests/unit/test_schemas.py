import pytest
from pydantic import ValidationError
from app.schemas.user_schema import (
    LoginSchema,
    UserCreateSchema,
    UserQuerySchema
)


def test_login_schema_valid():
    """Test valid login schema"""
    data = {
        'email': 'test@example.com',
        'password': 'password123'
    }
    schema = LoginSchema(**data)
    assert schema.email == 'test@example.com'
    assert schema.password == 'password123'


def test_login_schema_invalid_email():
    """Test login schema with invalid email"""
    data = {
        'email': 'invalid-email',
        'password': 'password123'
    }
    with pytest.raises(ValidationError) as exc_info:
        LoginSchema(**data)
    errors = exc_info.value.errors()
    assert any('email' in str(error) for error in errors)


def test_user_create_schema_defaults():
    """Test user creation schema with defaults"""
    data = {
        'email': 'user@example.com',
        'password': 'password123'
    }
    schema = UserCreateSchema(**data)
    assert schema.role == 'user'
    assert schema.status == 'active'
    assert schema.application_ids == []

