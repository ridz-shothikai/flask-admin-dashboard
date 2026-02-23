"""
Firestore Index Management API
Provides endpoints to create and manage Firestore indexes programmatically
"""
import os
import json
from flask import Blueprint, jsonify, current_app, request
from flask_jwt_extended import jwt_required, get_jwt
from typing import Dict, Any
import firebase_admin

firestore_indexes_bp = Blueprint('firestore_indexes', __name__)


def require_superadmin():
    """Decorator to require superadmin role"""
    claims = get_jwt()
    role = claims.get('role', 'staff')
    if role != 'superadmin':
        return jsonify({'error': 'Superadmin access required'}), 403
    return None


def load_indexes_file() -> Dict[str, Any]:
    """Load firestore.indexes.json file"""
    # Get project root directory (3 levels up from app/routes/)
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    indexes_file = os.path.join(project_root, 'firestore.indexes.json')
    
    if not os.path.exists(indexes_file):
        raise FileNotFoundError(f"firestore.indexes.json file not found at {indexes_file}")
    
    with open(indexes_file, 'r') as f:
        return json.load(f)




def create_indexes_using_firebase_cli() -> Dict[str, Any]:
    """
    Alternative method: Create indexes using Firebase CLI
    This requires Firebase CLI to be installed and authenticated.
    Note: Firebase CLI is the tool name, even though we're managing Firestore indexes.
    """
    import subprocess
    
    try:
        # Check if firebase CLI is available
        result = subprocess.run(
            ['firebase', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode != 0:
            raise Exception("Firebase CLI not found. Install it with: npm install -g firebase-tools")
        
        # Deploy indexes using Firebase CLI
        result = subprocess.run(
            ['firebase', 'deploy', '--only', 'firestore:indexes'],
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        if result.returncode != 0:
            raise Exception(f"Firebase CLI error: {result.stderr}")
        
        return {
            'status': 'success',
            'method': 'firebase_cli',
            'output': result.stdout
        }
        
    except FileNotFoundError:
        raise Exception(
            "Firebase CLI not found. "
            "Install it with: npm install -g firebase-tools"
        )
    except subprocess.TimeoutExpired:
        raise Exception("Firebase CLI command timed out")
    except Exception as e:
        raise Exception(f"Failed to create indexes via Firebase CLI: {str(e)}")


@firestore_indexes_bp.route('', methods=['GET'])
@jwt_required()
def get_indexes_config():
    """Get the current indexes configuration from firestore.indexes.json"""
    # Check permissions
    auth_error = require_superadmin()
    if auth_error:
        return auth_error
    
    try:
        indexes_config = load_indexes_file()
        return jsonify({
            'status': 'success',
            'indexes': indexes_config.get('indexes', []),
            'total': len(indexes_config.get('indexes', []))
        }), 200
    except FileNotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        current_app.logger.error(f"Error loading indexes config: {str(e)}")
        return jsonify({'error': f'Failed to load indexes configuration: {str(e)}'}), 500


@firestore_indexes_bp.route('/create', methods=['POST', 'OPTIONS'])
@jwt_required(optional=True)  # Allow OPTIONS request to proceed, POST will require valid token implicitly
def create_indexes():
    """
    Attempts to create Firestore composite indexes programmatically using the Admin API.
    """
    # Handle OPTIONS preflight request (Flask-CORS should handle this)
    if request.method == 'OPTIONS':
        return jsonify({"status": "OK"}), 200
    
    # If we reach here for a POST request, @jwt_required(optional=True) allowed it.
    # We rely on the frontend sending a valid token for POST requests.
    # A missing/invalid token would result in an error handled by Flask-JWT-Extended earlier.
    
    # Check permissions for POST requests
    auth_error = require_superadmin()
    if auth_error:
        return auth_error
    
    # --- Proceed with POST logic ---
    # Construct the path to firestore.indexes.json relative to the app's root
    backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    index_file_path = os.path.join(backend_root, 'firestore.indexes.json')
    
    if not os.path.exists(index_file_path):
        return jsonify({"status": "Error", "message": f"Index file not found at {index_file_path}"}), 404
    
    try:
        with open(index_file_path, 'r') as f:
            index_config = json.load(f)
    except Exception as e:
        return jsonify({"status": "Error", "message": f"Failed to read or parse index file: {str(e)}"}), 500
    
    indexes_to_create = index_config.get("indexes", [])
    
    if not indexes_to_create:
        return jsonify({"status": "Info", "message": "No composite indexes defined in firestore.indexes.json."}), 200
    
    # Get credentials (use the same logic as in db.py or rely on ADC)
    try:
        import google.auth
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
        from googleapiclient.errors import HttpError
        
        # Get credentials path from environment (same as db.py)
        credentials_path = os.environ.get('FIREBASE_CREDENTIALS_PATH', 'shothik-project-2cc7a51b6844.json')
        
        # Try to load from service account file first (like db.py does)
        if os.path.exists(credentials_path):
            # Load credentials from the JSON file with required scopes
            credentials = service_account.Credentials.from_service_account_file(
                credentials_path,
                scopes=['https://www.googleapis.com/auth/datastore', 'https://www.googleapis.com/auth/cloud-platform']
            )
            # Get project_id from the credentials file
            with open(credentials_path, 'r') as f:
                creds_data = json.load(f)
                project_id = creds_data.get('project_id')
        else:
            # Fall back to Application Default Credentials if file doesn't exist
            credentials, project_id = google.auth.default(
                scopes=['https://www.googleapis.com/auth/datastore', 'https://www.googleapis.com/auth/cloud-platform']
            )
        
        # Ensure project_id is available
        if not project_id:
            # Try to get from Firebase app as last resort
            try:
                firebase_app = firebase_admin.get_app()
                project_id = firebase_app.project_id
            except ValueError:
                pass  # Firebase app not initialized
        
        if not project_id:
            return jsonify({"status": "Error", "message": "Could not determine Google Cloud project ID."}), 500
            
    except ImportError as e:
        current_app.logger.error(f"ERROR: Missing required libraries: {e}")
        return jsonify({
            "status": "Error", 
            "message": f"Missing required libraries: {str(e)}. Install with: pip install google-api-python-client google-auth"
        }), 500
    except Exception as e:
        current_app.logger.error(f"ERROR: Failed to get credentials: {e}")
        return jsonify({"status": "Error", "message": f"Failed to get Google Cloud credentials: {str(e)}"}), 500
    
    # Build the Firestore Admin API client
    try:
        # Use version v1 for index management
        firestore_admin = build('firestore', 'v1', credentials=credentials, cache_discovery=False)
        
        # Use the configured database ID from environment
        database_name = os.environ.get('FIRESTORE_DATABASE_NAME', '(default)')
        database_id = database_name if database_name != '(default)' else '(default)'
        parent = f"projects/{project_id}/databases/{database_id}/collectionGroups"
        
        current_app.logger.info(f"Using Firestore Admin API parent path: {parent}")  # Log the path being used
    except Exception as e:
        current_app.logger.error(f"ERROR: Failed to build Firestore Admin API client: {e}")
        return jsonify({"status": "Error", "message": f"Failed to build Firestore Admin API client: {str(e)}"}), 500
    
    results = []
    has_errors = False
    
    for index_def in indexes_to_create:
        collection_id = index_def.get("collectionGroup")
        if not collection_id:
            results.append({"index": "Unknown", "status": "Skipped", "detail": "Missing 'collectionGroup' in definition."})
            has_errors = True
            continue
        
        # Construct the body for the API request
        # Map fields from JSON to API format
        api_fields = []
        for field in index_def.get("fields", []):
            api_field = {}
            if "fieldPath" in field:
                api_field["fieldPath"] = field["fieldPath"]
            if "order" in field:
                api_field["order"] = field["order"]
            # Add support for arrayConfig
            if "arrayConfig" in field:
                api_field["arrayConfig"] = field["arrayConfig"]
            
            if api_field:
                api_fields.append(api_field)
        
        if not api_fields:
            results.append({"index": collection_id, "status": "Skipped", "detail": "No valid 'fields' defined for index."})
            has_errors = True
            continue
        
        index_body = {
            "queryScope": index_def.get("queryScope", "COLLECTION"),  # Default to COLLECTION
            "fields": api_fields
        }
        
        index_name_str = f"{collection_id} ({', '.join([f['fieldPath']+' '+f.get('order','ASC') if 'order' in f else f['fieldPath']+' ARRAY_CONTAINS' for f in api_fields])})"  # For logging/reporting
        
        try:
            current_app.logger.info(f"Attempting to create index: {index_name_str}")
            request_obj = firestore_admin.projects().databases().collectionGroups().indexes().create(
                parent=f"{parent}/{collection_id}",
                body=index_body
            )
            
            # This returns a long-running operation object
            operation = request_obj.execute()
            
            current_app.logger.info(f"Index creation operation started for {index_name_str}: {operation.get('name')}")
            # Note: Index creation is asynchronous. We report initiation here.
            # Polling the operation status is possible but complex for a simple request.
            results.append({"index": index_name_str, "status": "Initiated", "detail": f"Operation: {operation.get('name')}"})
            
        except HttpError as e:
            error_content = e.content.decode('utf-8') if hasattr(e, 'content') else str(e)
            
            # Check if index already exists (409 Conflict or specific error message)
            if e.resp.status == 409 or 'already exists' in error_content.lower():
                current_app.logger.info(f"Index already exists: {index_name_str}")
                results.append({"index": index_name_str, "status": "Exists", "detail": "Index already exists."})
            else:
                current_app.logger.error(f"ERROR: API error creating index {index_name_str}: {e}")
                # Attempt to parse the error message for more specific info if possible
                error_detail = str(e)
                try:
                    # Google API errors often have structured details
                    error_info = json.loads(error_content).get('error', {})
                    error_detail = error_info.get('message', str(e))
                    if 'details' in error_info:
                        error_detail += f" Details: {json.dumps(error_info['details'])}"
                except (json.JSONDecodeError, KeyError, TypeError):
                    pass  # Keep original error string if parsing fails
                
                results.append({"index": index_name_str, "status": "Error", "detail": error_detail})
                has_errors = True
                
        except Exception as e:
            current_app.logger.error(f"ERROR: Unexpected error creating index {index_name_str}: {e}")
            results.append({"index": index_name_str, "status": "Error", "detail": f"Unexpected error: {str(e)}"})
            has_errors = True
    
    final_status_code = 207 if has_errors else 200  # Multi-Status if errors/skips occurred
    
    return jsonify({
        "status": "Completed" if not has_errors else "Completed with Errors/Skips",
        "message": "Firestore index creation process finished. Check details.",
        "results": results
    }), final_status_code


@firestore_indexes_bp.route('/validate', methods=['GET'])
@jwt_required()
def validate_indexes():
    """Validate the indexes configuration file"""
    # Check permissions
    auth_error = require_superadmin()
    if auth_error:
        return auth_error
    
    try:
        indexes_config = load_indexes_file()
        indexes = indexes_config.get('indexes', [])
        
        validation_errors = []
        validation_warnings = []
        
        # Validate each index configuration
        for idx, index_config in enumerate(indexes):
            # Check required fields
            if 'collectionGroup' not in index_config:
                validation_errors.append(f"Index {idx}: missing 'collectionGroup' field")
            
            if 'fields' not in index_config or not index_config['fields']:
                validation_errors.append(f"Index {idx}: missing or empty 'fields' array")
            
            # Validate fields
            if 'fields' in index_config:
                for field_idx, field_config in enumerate(index_config['fields']):
                    if 'fieldPath' not in field_config:
                        validation_errors.append(
                            f"Index {idx}, field {field_idx}: missing 'fieldPath'"
                        )
                    
                    # Check that either 'order' or 'arrayConfig' is specified
                    has_order = 'order' in field_config
                    has_array_config = 'arrayConfig' in field_config
                    
                    if not has_order and not has_array_config:
                        validation_errors.append(
                            f"Index {idx}, field {field_idx}: must have either 'order' or 'arrayConfig'"
                        )
                    
                    if has_order and has_array_config:
                        validation_warnings.append(
                            f"Index {idx}, field {field_idx}: has both 'order' and 'arrayConfig', 'arrayConfig' will be used"
                        )
                    
                    if has_order and field_config['order'] not in ['ASCENDING', 'DESCENDING']:
                        validation_errors.append(
                            f"Index {idx}, field {field_idx}: 'order' must be 'ASCENDING' or 'DESCENDING'"
                        )
                    
                    if has_array_config and field_config['arrayConfig'] != 'CONTAINS':
                        validation_errors.append(
                            f"Index {idx}, field {field_idx}: 'arrayConfig' must be 'CONTAINS'"
                        )
        
        is_valid = len(validation_errors) == 0
        
        return jsonify({
            'status': 'valid' if is_valid else 'invalid',
            'total_indexes': len(indexes),
            'errors': validation_errors,
            'warnings': validation_warnings,
            'message': 'Configuration is valid' if is_valid else f'Found {len(validation_errors)} error(s)'
        }), 200 if is_valid else 400
        
    except FileNotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        current_app.logger.error(f"Error validating indexes: {str(e)}")
        return jsonify({'error': f'Failed to validate indexes: {str(e)}'}), 500


@firestore_indexes_bp.route('/info', methods=['GET'])
@jwt_required()
def get_indexes_info():
    """Get information about the Firestore project and database"""
    # Check permissions
    auth_error = require_superadmin()
    if auth_error:
        return auth_error
    
    try:
        firebase_app = firebase_admin.get_app()
        project_id = firebase_app.project_id
        database_name = os.environ.get('FIRESTORE_DATABASE_NAME', '(default)')
        
        indexes_config = load_indexes_file()
        indexes = indexes_config.get('indexes', [])
        
        # Group indexes by collection
        collections = {}
        for index_config in indexes:
            collection = index_config.get('collectionGroup', 'unknown')
            if collection not in collections:
                collections[collection] = []
            collections[collection].append({
                'fields': index_config.get('fields', []),
                'queryScope': index_config.get('queryScope', 'COLLECTION')
            })
        
        return jsonify({
            'project_id': project_id,
            'database_name': database_name,
            'total_indexes': len(indexes),
            'collections': collections,
            'indexes_file': 'firestore.indexes.json'
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error getting indexes info: {str(e)}")
        return jsonify({'error': f'Failed to get indexes info: {str(e)}'}), 500


