import os
from flask import Flask
from flask_jwt_extended import JWTManager
from flask_cors import CORS

# Initialize extensions
jwt = JWTManager()


def create_app(config_object=None):
    """Application factory"""
    app = Flask(__name__)

    # Load configuration
    if config_object:
        app.config.from_object(config_object)
    else:
        from config.base import config
        # Flask 3.0 uses FLASK_ENV, fallback to 'development'
        env = os.environ.get('FLASK_ENV', 'development')
        app.config.from_object(config.get(env, config['default']))

    # Initialize extensions
    jwt.init_app(app)
    CORS(app)
    
    # Initialize Firestore
    from app.db import init_firestore
    init_firestore(app)

    # Register error handlers
    from app.utils.error_handler import register_error_handlers
    register_error_handlers(app)

    # Register blueprints
    from app.routes.auth import auth_bp
    from app.routes.users import users_bp
    from app.routes.applications import applications_bp
    from app.routes.dashboard import dashboard_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(applications_bp)
    app.register_blueprint(dashboard_bp)

    # Start background metrics collector (optional)
    # from app.utils.background_tasks import MetricsCollector
    # collector = MetricsCollector(app, interval=300)
    # collector.start()

    return app

