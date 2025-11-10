def test_login_success(client, app):
    """Test successful login"""
    from app import db
    from app.models import User
    with app.app_context():
        # Create test user
        user = User(email='test@example.com', role='user', status='active')
        user.set_password('password123')
        db.session.add(user)
        db.session.commit()

        # Attempt login
        response = client.post('/api/auth/login', json={
            'email': 'test@example.com',
            'password': 'password123'
        })
        assert response.status_code == 200
        assert 'access_token' in response.json
        assert 'refresh_token' in response.json


def test_login_invalid_credentials(client):
    """Test login with invalid credentials"""
    response = client.post('/api/auth/login', json={
        'email': 'nonexistent@example.com',
        'password': 'wrongpassword'
    })
    assert response.status_code == 401
    assert response.json['error']['code'] == 'INVALID_CREDENTIALS'

