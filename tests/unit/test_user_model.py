from app.models import User


def test_user_password_hashing(app):
    """Test password hashing and verification"""
    with app.app_context():
        user = User(email='test@example.com')
        user.set_password('password123')
        assert user.check_password('password123')
        assert not user.check_password('wrongpassword')


def test_user_to_dict(app):
    """Test user serialization"""
    with app.app_context():
        user = User(
            email='test@example.com',
            role='admin',
            status='active'
        )
        data = user.to_dict()
        assert data['email'] == 'test@example.com'
        assert data['role'] == 'admin'
        assert 'password_hash' not in data

