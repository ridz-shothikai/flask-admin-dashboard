# Firestore Integration Setup Guide

This application has been migrated from PostgreSQL to Google Cloud Firestore.

## Configuration

### 1. Firebase Service Account JSON

You need a Firebase service account JSON file.

**Environment Variable:**
```bash
FIREBASE_CREDENTIALS_PATH=path/to/your/service-account.json
```

### 2. Custom Database Name

To use a custom database name (not the default), set the following environment variable:

```bash
FIRESTORE_DATABASE_NAME=your-custom-database-name
```

**Important Notes:**
- Custom database names require Firestore in Native mode with multi-database support
- You must create the custom database in Firebase Console first
- If not set, it defaults to `(default)` database

### 3. Environment Variables

Add to your `.env` file:

```env
# Firebase/Firestore Configuration
FIREBASE_CREDENTIALS_PATH=path/to/your/service-account.json
FIRESTORE_DATABASE_NAME=(default)  # or your custom database name

# Other existing variables
SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret-key
```

## Firebase Console Setup

1. **Create Custom Database (if using custom name):**
   - Go to Firebase Console → Firestore Database
   - Click "Create Database" or "Add Database"
   - Choose "Native mode"
   - Enter your custom database name
   - Select your region

2. **Service Account Permissions:**
   - Ensure your service account has "Cloud Datastore User" or "Firestore User" role
   - The service account email should have access to your Firestore database

## Collections Structure

The application uses the following Firestore collections:

- `users` - User accounts
- `applications` - Application/region data
- `activity_logs` - System activity audit trail
- `system_metrics` - Historical system metrics
- `user_applications` - Many-to-many relationship between users and applications

## Key Differences from PostgreSQL

1. **No Migrations**: Firestore doesn't require schema migrations. Collections are created automatically.

2. **Document IDs**: Firestore uses auto-generated string IDs instead of integer IDs.

3. **Queries**: Some complex queries (like ILIKE searches) are handled in-memory after fetching documents.

4. **Relationships**: Many-to-many relationships are stored as arrays of document IDs in user documents, plus a separate `user_applications` collection for tracking.

5. **Indexes**: Firestore may require composite indexes for certain queries. Check Firebase Console for index creation prompts.

## Running the Application

1. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Set Environment Variables:**
   ```bash
   # Copy .env.example to .env and configure
   cp .env.example .env
   ```

3. **Run the Application:**
   ```bash
   python run.py
   ```

4. **Seed Sample Data (Optional):**
   ```bash
   python scripts/seed_data.py
   ```

## Migration Notes

- All SQLAlchemy models have been converted to Firestore document models
- Database operations now use Firestore client instead of SQLAlchemy sessions
- Pagination and filtering are handled in-memory for complex queries
- Timestamps are stored as Firestore Timestamp objects

## Troubleshooting

1. **"Firestore not initialized" error:**
   - Ensure `init_firestore()` is called in `app/__init__.py`
   - Check that your service account JSON file exists and is valid

2. **Permission errors:**
   - Verify service account has proper IAM roles
   - Check that the database exists in Firebase Console

3. **Custom database not found:**
   - Ensure the database is created in Firebase Console
   - Verify the database name matches exactly (case-sensitive)

