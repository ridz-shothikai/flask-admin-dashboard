"""
Firestore database initialization and utilities
"""
import os
import firebase_admin
from firebase_admin import credentials, firestore
from google.cloud.firestore_v1 import Client

# Global Firestore client
db: Client = None


def init_firestore(app=None):
    """Initialize Firestore connection"""
    global db
    
    if db is not None:
        return db
    
    # Get configuration
    credentials_path = os.environ.get('FIREBASE_CREDENTIALS_PATH', 'shothik-project-2cc7a51b6844.json')
    database_name = os.environ.get('FIRESTORE_DATABASE_NAME', '(default)')
    
    # Check if Firebase app is already initialized
    app_initialized = False
    try:
        firebase_admin.get_app()
        app_initialized = True
    except ValueError:
        app_initialized = False
    
    # Initialize Firebase Admin SDK if not already initialized
    if not app_initialized:
        if os.path.exists(credentials_path):
            cred = credentials.Certificate(credentials_path)
            firebase_admin.initialize_app(cred)
        else:
            # Try to use default credentials (for production environments like GCP)
            firebase_admin.initialize_app()
    
    # Get Firestore client with custom database name
    # Note: Custom database names require Firestore in Native mode with multi-database support
    # Ensure your Firebase project has multi-database enabled in Firebase Console
    if database_name == '(default)':
        db = firestore.client()
    else:
        # Use custom database name
        # For custom databases, we need to use google.cloud.firestore.Client directly
        # with the database parameter
        from google.cloud import firestore as gcp_firestore
        
        # Get project ID and credentials from the initialized Firebase app
        firebase_app = firebase_admin.get_app()
        project_id = firebase_app.project_id
        
        # Get credentials from the Firebase app
        # The credentials are already loaded in the Firebase app
        if os.path.exists(credentials_path):
            # Load credentials from the JSON file
            from google.oauth2 import service_account
            creds = service_account.Credentials.from_service_account_file(credentials_path)
            db = gcp_firestore.Client(project=project_id, credentials=creds, database=database_name)
        else:
            # Use default credentials (for production environments like GCP)
            db = gcp_firestore.Client(project=project_id, database=database_name)
    
    return db


def get_db():
    """Get Firestore database client"""
    global db
    if db is None:
        raise RuntimeError("Firestore not initialized. Call init_firestore() first.")
    return db

