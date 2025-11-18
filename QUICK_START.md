# Quick Start Guide - Flask Admin Dashboard

This guide will help you get the Flask Admin Dashboard up and running quickly.

## Prerequisites

- ✅ Python 3.8+ (You have Python 3.12.3)
- ✅ PostgreSQL database (running locally or in Docker)
- ✅ pip (Python package manager)

---

## Step-by-Step Setup

### Step 1: Activate Virtual Environment

If you already have a virtual environment:

```bash
cd /home/morshed/own-folder/Documents/flask-admin-dashboard
source venv/bin/activate
```

If you don't have a virtual environment yet:

```bash
cd /home/morshed/own-folder/Documents/flask-admin-dashboard
python3 -m venv venv
source venv/bin/activate
```

**Note:** On Windows, use: `venv\Scripts\activate`

---

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

This will install all required packages including:
- Flask and Flask extensions
- PostgreSQL adapter (psycopg2-binary)
- SAML library (python3-saml)
- Pydantic for validation
- And more...

---

### Step 3: Configure Environment Variables

You already have a `.env` file. Verify it contains the correct database connection:

```bash
# Check your .env file
cat .env | grep DATABASE_URL
```

**Required `.env` variables:**
```env
# Database (REQUIRED)
DATABASE_URL=postgresql://username:password@localhost:5432/admin_dashboard

# Flask Configuration
FLASK_APP=run.py
FLASK_ENV=development
SECRET_KEY=your-secret-key-change-this-in-production
DEBUG=True
PORT=5000

# JWT Configuration
JWT_SECRET_KEY=your-jwt-secret-key-change-this-in-production
JWT_ACCESS_TOKEN_EXPIRES=3600
JWT_REFRESH_TOKEN_EXPIRES=2592000

# CORS (for frontend)
CORS_ORIGINS=http://localhost:3000,http://localhost:5000
FRONTEND_URL=http://localhost:3000

# SAML (optional - set SAML_ENABLED=false if not using SSO)
SAML_ENABLED=false
```

**Important:** Update `DATABASE_URL` with your actual PostgreSQL credentials!

---

### Step 4: Setup Database

#### Option A: Using Existing PostgreSQL Database

1. **Create the database** (if it doesn't exist):
   ```bash
   # Connect to PostgreSQL
   psql -U your_username -d postgres
   
   # Create database
   CREATE DATABASE admin_dashboard;
   
   # Exit
   \q
   ```

2. **Run database migrations**:
   ```bash
   flask db upgrade
   ```

#### Option B: Using Docker PostgreSQL

If you have PostgreSQL in Docker:

```bash
# Create database in Docker container
docker exec -it <container_name> psql -U <username> -c "CREATE DATABASE admin_dashboard;"

# Then run migrations
flask db upgrade
```

#### Option C: Auto-create Tables (Development Only)

The `run.py` script will automatically create tables if they don't exist:

```bash
python run.py
```

This will create all tables automatically (but migrations are recommended for production).

---

### Step 5: Seed Sample Data (Optional)

To populate the database with sample users and applications:

```bash
python scripts/seed_data.py
```

This creates:
- **6 sample users:**
  - `superadmin@example.com` / `SuperAdmin123!`
  - `admin@example.com` / `Admin123!`
  - `user1@example.com` / `User123!`
  - `user2@example.com` / `User123!`
  - `inactive@example.com` / `User123!` (inactive account)
  - `newuser@example.com` / `User123!`
- **5 sample applications:**
  - Dashboard
  - Region 14
  - Region 2
  - Analytics
  - Legacy System

---

### Step 6: Run the Application

#### Method 1: Using run.py (Recommended)

```bash
python run.py
```

The application will start on: **http://localhost:5000**

#### Method 2: Using Flask CLI

```bash
export FLASK_APP=run.py
export FLASK_ENV=development
flask run
```

#### Method 3: Using Python Directly

```bash
python -m flask run
```

---

## Verify It's Working

### 1. Check Server is Running

You should see output like:
```
 * Running on http://0.0.0.0:5000
 * Debug mode: on
```

### 2. Test the API

Open a new terminal and test the login endpoint:

```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "Admin123!"
  }'
```

**Expected Response:**
```json
{
  "message": "Login successful",
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": 2,
    "email": "admin@example.com",
    "role": "admin",
    ...
  }
}
```

### 3. Test Protected Endpoint

```bash
# First, get the access_token from the login response above
TOKEN="your_access_token_here"

curl -X GET http://localhost:5000/api/auth/me \
  -H "Authorization: Bearer $TOKEN"
```

---

## Common Commands

### Database Migrations

```bash
# Create a new migration
flask db migrate -m "Description of changes"

# Apply migrations
flask db upgrade

# Rollback last migration
flask db downgrade
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app

# Run specific test file
pytest tests/unit/test_user_model.py
```

### Check Database Connection

```bash
# Test database connection
python -c "from app import create_app, db; app = create_app(); app.app_context().push(); print('Database:', db.engine.url)"
```

---

## Troubleshooting

### Issue: "Module not found" errors

**Solution:**
```bash
# Make sure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

### Issue: Database connection error

**Error:** `sqlalchemy.exc.OperationalError: could not connect to server`

**Solution:**
1. Verify PostgreSQL is running:
   ```bash
   # Check if PostgreSQL is running
   sudo systemctl status postgresql
   # OR for Docker
   docker ps | grep postgres
   ```

2. Check your `.env` file has correct `DATABASE_URL`:
   ```bash
   cat .env | grep DATABASE_URL
   ```

3. Test connection manually:
   ```bash
   psql -U your_username -d admin_dashboard
   ```

### Issue: Port 5000 already in use

**Solution:**
```bash
# Option 1: Change port in .env
PORT=5001

# Option 2: Kill process using port 5000
lsof -ti:5000 | xargs kill -9

# Option 3: Use different port when running
python run.py  # Will use PORT from .env
```

### Issue: Migration errors

**Solution:**
```bash
# Check current migration status
flask db current

# If needed, stamp to current revision
flask db stamp head

# Then upgrade
flask db upgrade
```

### Issue: "No such user" when logging in

**Solution:**
```bash
# Seed the database with sample users
python scripts/seed_data.py
```

Then try logging in with:
- Email: `admin@example.com`
- Password: `Admin123!`

---

## API Endpoints Quick Reference

### Base URL
```
http://localhost:5000/api
```

### Authentication
- `POST /api/auth/login` - Login with email/password
- `POST /api/auth/refresh` - Refresh access token
- `GET /api/auth/me` - Get current user
- `POST /api/auth/logout` - Logout
- `GET /api/auth/saml/login` - Initiate SAML SSO (if enabled)

### Users (Admin only)
- `GET /api/users` - List all users
- `POST /api/users` - Create user
- `GET /api/users/:id` - Get user by ID
- `PUT /api/users/:id` - Update user
- `DELETE /api/users/:id` - Delete user

### Applications
- `GET /api/applications` - List all applications
- `POST /api/applications` - Create application (Admin only)
- `GET /api/applications/:id` - Get application by ID
- `PUT /api/applications/:id` - Update application (Admin only)
- `DELETE /api/applications/:id` - Delete application (Admin only)

### Dashboard
- `GET /api/dashboard/stats` - Get dashboard statistics
- `GET /api/dashboard/health` - Get system health metrics
- `GET /api/dashboard/activity` - Get recent activity logs

---

## Using Postman

1. **Import Collection:**
   - Create a new collection: "Flask Admin Dashboard"
   - Set base URL: `http://localhost:5000/api`

2. **Login First:**
   - `POST /api/auth/login`
   - Save `access_token` and `refresh_token` to collection variables

3. **Use Token:**
   - Set Authorization: Bearer Token
   - Token: `{{access_token}}`

See `README.md` for detailed Postman setup instructions.

---

## Next Steps

1. ✅ **Application is running** - You can now make API requests
2. 📖 **Read API Documentation** - See `README.md` for complete API reference
3. 🔐 **Test Authentication** - Try logging in with sample users
4. 🧪 **Run Tests** - Verify everything works: `pytest`
5. 🚀 **Deploy** - When ready, deploy to production

---

## Production Deployment

For production, make sure to:

1. **Set strong secrets:**
   ```env
   SECRET_KEY=<generate-strong-random-key>
   JWT_SECRET_KEY=<generate-strong-random-key>
   ```

2. **Disable debug mode:**
   ```env
   DEBUG=False
   FLASK_ENV=production
   ```

3. **Use production database:**
   ```env
   DATABASE_URL=postgresql://user:pass@prod-host:5432/admin_dashboard
   ```

4. **Use a production server:**
   ```bash
   gunicorn -w 4 -b 0.0.0.0:5000 run:app
   ```

5. **Enable HTTPS** - Always use HTTPS in production

---

## Need Help?

- 📖 Check `README.md` for detailed documentation
- 🔍 Review error messages in terminal
- 📝 Check application logs
- 🧪 Run tests to verify setup: `pytest`

---

**Happy Coding! 🚀**

