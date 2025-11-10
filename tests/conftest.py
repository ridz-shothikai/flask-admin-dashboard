import pytest
from app import create_app, db
from app.models import User, Application
from config.base import Config


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'postgresql://localhost/admin_dashboard_test'
    JWT_SECRET_KEY = 'test-secret-key'


@pytest.fixture
def app():
    """Create application for testing"""
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()


@pytest.fixture
def auth_headers(client):
    """Create authenticated headers"""
    # Create a test user
    from app import db
    from app.models import User
    user = User(email='admin@test.com', role='admin', status='active')
    user.set_password('password123')
    db.session.add(user)
    db.session.commit()

    # Login
    response = client.post('/api/auth/login', json={
        'email': 'admin@test.com',
        'password': 'password123'
    })
    token = response.json['access_token']
    return {
        'Authorization': f'Bearer {token}'
    }

