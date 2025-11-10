import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:

    """Base configuration"""
    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-prod'
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://localhost/admin_dashboard'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # JWT
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-secret-key'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(
        seconds=int(os.environ.get('JWT_ACCESS_TOKEN_EXPIRES', 3600))
    )
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(
        seconds=int(os.environ.get('JWT_REFRESH_TOKEN_EXPIRES', 2592000))
    )
    # CORS
    CORS_HEADERS = 'Content-Type'
    # Pagination
    ITEMS_PER_PAGE = 20

class DevelopmentConfig(Config):

    """Development configuration"""
    DEBUG = True
    
class ProductionConfig(Config):

    """Production configuration"""
    DEBUG = False

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}