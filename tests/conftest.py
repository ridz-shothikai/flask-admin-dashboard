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
def auth_headers(client, app):
    """Create authenticated headers"""
    # Create a test user
    from app import db
    from app.models import User
    user = User(email='admin@test.com', role='superuser', status='active')
    user.set_password('password123')
    db.session.add(user)
    db.session.commit()

    # Get API prefix from config
    api_prefix = app.config.get('API_PREFIX', '/api')
    
    # Login
    response = client.post(f'{api_prefix}/auth/login', json={
        'email': 'admin@test.com',
        'password': 'password123'
    })
    token = response.json['access_token']
    return {
        'Authorization': f'Bearer {token}'
    }


@pytest.fixture
def api_prefix(app):
    """Get API prefix from app config"""
    return app.config.get('API_PREFIX', '/api')

