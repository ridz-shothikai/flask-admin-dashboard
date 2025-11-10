# Flask Admin Dashboard - Complete Documentation

## Table of Contents
1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Features](#features)
4. [Technology Stack](#technology-stack)
5. [Project Structure](#project-structure)
6. [Setup Instructions](#setup-instructions)
7. [Database Configuration](#database-configuration)
8. [Running the Application](#running-the-application)
9. [API Documentation](#api-documentation)
10. [Using Postman](#using-postman)
11. [Authentication Flow](#authentication-flow)
12. [Error Handling](#error-handling)
13. [Testing](#testing)

---

## Project Overview

The Flask Admin Dashboard is a production-ready RESTful API backend built with Flask, SQLAlchemy, and Pydantic. It provides a complete admin dashboard system with user management, application management, activity logging, and system monitoring capabilities.

### Key Features
- **User Management**: CRUD operations for users with role-based access control
- **Application Management**: Manage applications/regions with user assignments
- **Activity Logging**: Comprehensive audit trail of all system activities
- **System Monitoring**: Real-time system health metrics (CPU, memory, disk)
- **JWT Authentication**: Secure token-based authentication with refresh tokens
- **Pydantic Validation**: Type-safe request/response validation
- **Role-Based Access Control**: Three-tier role system (user, admin, superadmin)

---

## Architecture

### Application Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Client (Postman/Frontend)             │
└────────────────────────────┬─────────────────────────────────┘
                             │ HTTP/HTTPS
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                    Flask Application                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Routes     │  │  Validation  │  │ Error Handler│      │
│  │  (Blueprints)│  │  (Pydantic)  │  │              │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                 │                 │               │
│  ┌──────▼─────────────────▼─────────────────▼───────┐      │
│  │              Business Logic Layer                  │      │
│  └──────┬─────────────────────────────────────────────┘      │
│         │                                                     │
│  ┌──────▼─────────────────────────────────────────────┐      │
│  │              Data Access Layer (SQLAlchemy)         │      │
│  └──────┬─────────────────────────────────────────────┘      │
└─────────┼─────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│              PostgreSQL Database (Docker)                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │  Users   │  │   Apps   │  │ Activity │  │ Metrics  │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### Request Flow

1. **Request** → Client sends HTTP request to Flask route
2. **Validation** → Pydantic schema validates request data
3. **Authentication** → JWT token verified (if protected route)
4. **Authorization** → Role-based access control checked
5. **Business Logic** → Route handler processes request
6. **Database** → SQLAlchemy ORM executes queries
7. **Response** → JSON response returned to client
8. **Activity Log** → Action logged to database (if applicable)

---

## Features

### User Management
- Create, read, update, delete users
- Role assignment (user, admin, superadmin)
- Status management (active, inactive)
- Application assignments
- Search and filtering
- Pagination

### Application Management
- Create, read, update, delete applications
- Status management (active, inactive, maintenance)
- User assignment tracking
- Search and filtering

### Authentication & Security
- JWT-based authentication
- Access and refresh tokens
- Password hashing with bcrypt
- Role-based access control
- Token refresh mechanism

### Activity Logging
- Automatic logging of all system activities
- User login/logout tracking
- CRUD operation logging
- IP address and user agent tracking

### System Monitoring
- Real-time CPU, memory, and disk usage
- Historical metrics storage
- Health endpoint for monitoring

---

## Technology Stack

### Backend Framework
- **Flask 3.0.0**: Web framework
- **Flask-SQLAlchemy 3.1.1**: ORM for database operations
- **Flask-Migrate 4.0.5**: Database migrations
- **Flask-JWT-Extended 4.6.0**: JWT authentication
- **Flask-CORS 4.0.0**: Cross-origin resource sharing

### Database
- **PostgreSQL**: Primary database (running in Docker)
- **psycopg2-binary 2.9.9**: PostgreSQL adapter

### Validation & Serialization
- **Pydantic 2.5.3**: Data validation and settings management
- **email-validator 2.1.0**: Email validation

### Security
- **bcrypt 4.1.2**: Password hashing

### Monitoring
- **psutil 5.9.6**: System and process utilities

### Testing
- **pytest 7.4.3**: Testing framework
- **pytest-flask 1.3.0**: Flask testing utilities

---

## Project Structure

```
flask-admin-dashboard/
├── app/
│   ├── __init__.py              # Application factory
│   ├── models/                  # Database models
│   │   ├── __init__.py
│   │   ├── user.py              # User model
│   │   ├── application.py       # Application model
│   │   ├── activity.py          # ActivityLog model
│   │   └── metrics.py           # SystemMetric model
│   ├── routes/                  # API endpoints
│   │   ├── auth.py              # Authentication routes
│   │   ├── users.py             # User management routes
│   │   ├── applications.py     # Application routes
│   │   └── dashboard.py         # Dashboard routes
│   ├── schemas/                 # Pydantic validation schemas
│   │   ├── user_schema.py       # User validation schemas
│   │   └── application_schema.py # Application schemas
│   ├── utils/                   # Utility functions
│   │   ├── validation.py        # Pydantic decorators
│   │   ├── error_handler.py     # Error handlers
│   │   ├── monitoring.py        # System monitoring
│   │   └── background_tasks.py  # Background jobs
│   └── middleware/              # Middleware
│       └── activity_logger.py   # Activity logging
├── config/
│   └── base.py                  # Configuration
├── tests/                        # Test files
│   ├── conftest.py
│   ├── unit/
│   └── integration/
├── scripts/
│   └── seed_data.py             # Database seeding
├── migrations/                   # Database migrations
├── .env                          # Environment variables
├── .env.example                  # Environment template
├── requirements.txt              # Python dependencies
└── run.py                        # Application entry point
```

---

## Setup Instructions

### Prerequisites
- Python 3.8+
- PostgreSQL (running in Docker)
- pip (Python package manager)

### Step 1: Clone and Navigate
```bash
cd flask-admin-dashboard
```

### Step 2: Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment
Create a `.env` file (or copy from `.env.example`):
```bash
cp .env.example .env
```

Edit `.env` with your database credentials:
```env
DATABASE_URL=postgresql://raguser:ragpass123@localhost:5432/admin_dashboard
SECRET_KEY=your-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-key-here
```

### Step 5: Setup Database
```bash
# Create database (if using Docker PostgreSQL)
docker exec rag_postgres psql -U raguser -d ragdb -c "CREATE DATABASE admin_dashboard;"

# Or create tables directly
python run.py  # This will create tables automatically
```

### Step 6: Seed Sample Data (Optional)
```bash
python scripts/seed_data.py
```

This creates:
- 6 sample users (superadmin, admin, regular users)
- 5 sample applications

### Step 7: Run the Application
```bash
python run.py
```

The application will start on `http://localhost:5000`

---

## Database Configuration

### Docker PostgreSQL Setup

If using Docker PostgreSQL:

1. **Check running container:**
   ```bash
   docker ps | grep postgres
   ```

2. **Get database credentials:**
   ```bash
   docker exec <container_name> env | grep POSTGRES
   ```

3. **Create database:**
   ```bash
   docker exec <container_name> psql -U <user> -d <default_db> -c "CREATE DATABASE admin_dashboard;"
   ```

4. **Update .env file:**
   ```env
   DATABASE_URL=postgresql://<user>:<password>@localhost:5432/admin_dashboard
   ```

### Database Tables

The application creates the following tables:

1. **users**: User accounts and profiles
2. **applications**: Applications/regions
3. **activity_logs**: System activity audit trail
4. **system_metrics**: Historical system metrics
5. **user_applications**: Many-to-many relationship table

---

## Running the Application

### Development Mode
```bash
python run.py
```

### Using Flask CLI
```bash
export FLASK_APP=run.py
export FLASK_ENV=development
flask run
```

### Production Mode
```bash
export FLASK_ENV=production
gunicorn -w 4 -b 0.0.0.0:5000 run:app
```

---

## API Documentation

### Base URL
```
http://localhost:5000/api
```

### Authentication

All protected endpoints require a JWT token in the Authorization header:
```
Authorization: Bearer <access_token>
```

### Response Format

**Success Response:**
```json
{
  "message": "Operation successful",
  "data": { ... }
}
```

**Error Response:**
```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": [ ... ]
  }
}
```

---

## Using Postman

### Setting Up Postman

1. **Create a new Collection**: "Flask Admin Dashboard"

2. **Set Collection Variables:**
   - `base_url`: `http://localhost:5000/api`
   - `access_token`: (will be set after login)
   - `refresh_token`: (will be set after login)

3. **Create Environment Variables** (optional):
   - `base_url`: `http://localhost:5000/api`
   - `access_token`: ``
   - `refresh_token`: ``

### Authentication Setup

1. **Login Request** → Save tokens to variables
2. **Use tokens** in Authorization header for protected routes
3. **Refresh token** when access token expires

---

## Authentication Flow

### 1. Login

**Endpoint:** `POST /api/auth/login`

**Request Body:**
```json
{
  "email": "admin@example.com",
  "password": "Admin123!"
}
```

**Response:**
```json
{
  "message": "Login successful",
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": 1,
    "email": "admin@example.com",
    "role": "admin",
    "status": "active",
    ...
  }
}
```

**Postman Setup:**
1. Create request: `POST {{base_url}}/auth/login`
2. Body → raw → JSON
3. Add Tests tab:
```javascript
// Save tokens to variables
pm.environment.set("access_token", pm.response.json().access_token);
pm.environment.set("refresh_token", pm.response.json().refresh_token);
```

### 2. Using Access Token

**For Protected Routes:**
1. Go to **Authorization** tab
2. Select **Bearer Token**
3. Token: `{{access_token}}`

Or manually in Headers:
```
Authorization: Bearer {{access_token}}
```

### 3. Refresh Token

**Endpoint:** `POST /api/auth/refresh`

**Headers:**
```
Authorization: Bearer {{refresh_token}}
```

**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

**Postman Setup:**
1. Create request: `POST {{base_url}}/auth/refresh`
2. Authorization → Bearer Token → `{{refresh_token}}`
3. Add Tests:
```javascript
pm.environment.set("access_token", pm.response.json().access_token);
```

### 4. Get Current User

**Endpoint:** `GET /api/auth/me`

**Headers:**
```
Authorization: Bearer {{access_token}}
```

**Response:**
```json
{
  "id": 1,
  "email": "admin@example.com",
  "role": "admin",
  "status": "active",
  ...
}
```

### 5. Logout

**Endpoint:** `POST /api/auth/logout`

**Headers:**
```
Authorization: Bearer {{access_token}}
```

---

## API Endpoints

### Authentication Endpoints

#### Login
- **Method:** `POST`
- **URL:** `/api/auth/login`
- **Auth:** Not required
- **Body:**
  ```json
  {
    "email": "admin@example.com",
    "password": "Admin123!"
  }
  ```

#### Refresh Token
- **Method:** `POST`
- **URL:** `/api/auth/refresh`
- **Auth:** Refresh token required
- **Body:** None

#### Get Current User
- **Method:** `GET`
- **URL:** `/api/auth/me`
- **Auth:** Access token required
- **Body:** None

#### Logout
- **Method:** `POST`
- **URL:** `/api/auth/logout`
- **Auth:** Access token required
- **Body:** None

---

### User Management Endpoints

#### Get All Users
- **Method:** `GET`
- **URL:** `/api/users`
- **Auth:** Access token (admin/superadmin only)
- **Query Parameters:**
  - `page` (int, default: 1): Page number
  - `per_page` (int, default: 20, max: 100): Items per page
  - `search` (string, optional): Search in email, first_name, last_name
  - `role` (string, optional): Filter by role (user, admin, superadmin)
  - `status` (string, optional): Filter by status (active, inactive)
  - `sort` (string, default: created_date): Sort field
  - `order` (string, default: desc): Sort order (asc, desc)

**Example:**
```
GET /api/users?page=1&per_page=10&role=admin&status=active&search=john
```

**Response:**
```json
{
  "users": [
    {
      "id": 1,
      "email": "admin@example.com",
      "role": "admin",
      "status": "active",
      "first_name": "John",
      "last_name": "Doe",
      "created_date": "2024-01-01T00:00:00",
      "last_login": "2024-01-15T10:30:00",
      "assigned_applications": [...]
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 10,
    "total": 25,
    "pages": 3,
    "has_next": true,
    "has_prev": false
  }
}
```

#### Create User
- **Method:** `POST`
- **URL:** `/api/users`
- **Auth:** Access token (admin/superadmin only)
- **Body:**
  ```json
  {
    "email": "newuser@example.com",
    "password": "Password123!",
    "role": "user",
    "status": "active",
    "first_name": "Jane",
    "last_name": "Smith",
    "application_ids": [1, 2]
  }
  ```

**Response:**
```json
{
  "message": "User created successfully",
  "user": { ... }
}
```

#### Get User by ID
- **Method:** `GET`
- **URL:** `/api/users/<user_id>`
- **Auth:** Access token (admin/superadmin only)
- **Body:** None

#### Update User
- **Method:** `PUT`
- **URL:** `/api/users/<user_id>`
- **Auth:** Access token (admin/superadmin only)
- **Body:** (All fields optional, at least one required)
  ```json
  {
    "email": "updated@example.com",
    "password": "NewPassword123!",
    "role": "admin",
    "status": "active",
    "first_name": "Updated",
    "last_name": "Name",
    "application_ids": [1, 2, 3]
  }
  ```

#### Delete User
- **Method:** `DELETE`
- **URL:** `/api/users/<user_id>`
- **Auth:** Access token (admin/superadmin only)
- **Body:** None

**Note:** Cannot delete your own account.

---

### Application Management Endpoints

#### Get All Applications
- **Method:** `GET`
- **URL:** `/api/applications`
- **Auth:** Access token required
- **Query Parameters:**
  - `page` (int, default: 1)
  - `per_page` (int, default: 20, max: 100)
  - `search` (string, optional): Search in name
  - `status` (string, optional): Filter by status (active, inactive, maintenance)
  - `sort` (string, default: name)
  - `order` (string, default: asc)

#### Create Application
- **Method:** `POST`
- **URL:** `/api/applications`
- **Auth:** Access token (admin/superadmin only)
- **Body:**
  ```json
  {
    "name": "New Application",
    "description": "Application description",
    "url": "https://app.example.com",
    "status": "active"
  }
  ```

#### Get Application by ID
- **Method:** `GET`
- **URL:** `/api/applications/<app_id>`
- **Auth:** Access token required
- **Body:** None

#### Update Application
- **Method:** `PUT`
- **URL:** `/api/applications/<app_id>`
- **Auth:** Access token (admin/superadmin only)
- **Body:** (All fields optional)
  ```json
  {
    "name": "Updated Name",
    "description": "Updated description",
    "url": "https://updated.example.com",
    "status": "maintenance"
  }
  ```

#### Delete Application
- **Method:** `DELETE`
- **URL:** `/api/applications/<app_id>`
- **Auth:** Access token (admin/superadmin only)
- **Body:** None

---

### Dashboard Endpoints

#### Get Dashboard Statistics
- **Method:** `GET`
- **URL:** `/api/dashboard/stats`
- **Auth:** Access token required
- **Body:** None

**Response:**
```json
{
  "users": {
    "total": 25,
    "active": 20,
    "inactive": 5,
    "by_role": {
      "user": 15,
      "admin": 5,
      "superadmin": 5
    },
    "recent_logins": 12
  },
  "applications": {
    "total": 10,
    "active": 8
  },
  "activity": {
    "recent_count": 150
  }
}
```

#### Get System Health
- **Method:** `GET`
- **URL:** `/api/dashboard/health`
- **Auth:** Access token required
- **Body:** None

**Response:**
```json
{
  "cpu": {
    "usage_percent": 45.2
  },
  "memory": {
    "usage_percent": 62.5,
    "total_bytes": 17179869184,
    "used_bytes": 10737418240,
    "total_gb": 16.0,
    "used_gb": 10.0
  },
  "disk": {
    "usage_percent": 42.3,
    "total_bytes": 107374182400,
    "used_bytes": 45415292928,
    "total_gb": 100.0,
    "used_gb": 42.3
  },
  "timestamp": "2024-01-15T10:30:00"
}
```

#### Get Recent Activity
- **Method:** `GET`
- **URL:** `/api/dashboard/activity`
- **Auth:** Access token required
- **Body:** None

**Response:**
```json
{
  "activities": [
    {
      "id": 1,
      "event_type": "user_login",
      "user_id": 1,
      "user_email": "admin@example.com",
      "description": "User admin@example.com logged in",
      "ip_address": "192.168.1.1",
      "timestamp": "2024-01-15T10:30:00"
    }
  ]
}
```

#### Get Metrics History
- **Method:** `GET`
- **URL:** `/api/dashboard/metrics/history`
- **Auth:** Access token required
- **Body:** None

**Response:**
```json
{
  "metrics": [
    {
      "id": 1,
      "cpu_usage": 45.2,
      "memory_usage": 62.5,
      "disk_usage": 42.3,
      "timestamp": "2024-01-15T10:30:00"
    }
  ]
}
```

---

## Error Handling

### Error Response Format
```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": [ ... ]
  }
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 400 | Invalid input data |
| `UNAUTHORIZED` | 401 | Authentication required |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `EMAIL_EXISTS` | 409 | Email already in use |
| `APPLICATION_EXISTS` | 409 | Application name already exists |
| `INVALID_CREDENTIALS` | 401 | Invalid email or password |
| `ACCOUNT_INACTIVE` | 403 | Account is deactivated |
| `CANNOT_DELETE_SELF` | 400 | Cannot delete own account |
| `INTERNAL_SERVER_ERROR` | 500 | Server error |

### Example Error Responses

**Validation Error:**
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": [
      {
        "loc": ["body", "email"],
        "msg": "value is not a valid email address",
        "type": "value_error.email"
      }
    ]
  }
}
```

**Unauthorized:**
```json
{
  "error": {
    "code": "UNAUTHORIZED",
    "message": "Authentication required"
  }
}
```

**Forbidden:**
```json
{
  "error": {
    "code": "FORBIDDEN",
    "message": "Admin access required"
  }
}
```

---

## Postman Collection Setup

### Step-by-Step Postman Setup

#### 1. Create Collection
1. Open Postman
2. Click **New** → **Collection**
3. Name: "Flask Admin Dashboard"

#### 2. Set Collection Variables
1. Click on collection → **Variables** tab
2. Add variables:
   - `base_url`: `http://localhost:5000/api`
   - `access_token`: (leave empty, will be set automatically)
   - `refresh_token`: (leave empty, will be set automatically)

#### 3. Create Folder Structure
Create folders:
- `Authentication`
- `Users`
- `Applications`
- `Dashboard`

#### 4. Setup Authentication Request

**Request:** `POST {{base_url}}/auth/login`

**Body (raw JSON):**
```json
{
  "email": "admin@example.com",
  "password": "Admin123!"
}
```

**Tests Tab:**
```javascript
if (pm.response.code === 200) {
    const response = pm.response.json();
    pm.collectionVariables.set("access_token", response.access_token);
    pm.collectionVariables.set("refresh_token", response.refresh_token);
    pm.collectionVariables.set("user_id", response.user.id);
}
```

#### 5. Setup Authorization for Collection
1. Click collection → **Authorization** tab
2. Type: **Bearer Token**
3. Token: `{{access_token}}`

This will automatically apply to all requests in the collection.

#### 6. Create Sample Requests

**Get All Users:**
- Method: `GET`
- URL: `{{base_url}}/users?page=1&per_page=10`
- Authorization: Inherit from collection

**Create User:**
- Method: `POST`
- URL: `{{base_url}}/users`
- Body:
```json
{
  "email": "newuser@example.com",
  "password": "Password123!",
  "role": "user",
  "status": "active",
  "first_name": "New",
  "last_name": "User"
}
```

---

## Complete Postman Request Examples

### Authentication

#### 1. Login
```
POST http://localhost:5000/api/auth/login
Content-Type: application/json

{
  "email": "admin@example.com",
  "password": "Admin123!"
}
```

#### 2. Refresh Token
```
POST http://localhost:5000/api/auth/refresh
Authorization: Bearer {{refresh_token}}
```

#### 3. Get Current User
```
GET http://localhost:5000/api/auth/me
Authorization: Bearer {{access_token}}
```

#### 4. Logout
```
POST http://localhost:5000/api/auth/logout
Authorization: Bearer {{access_token}}
```

---

### User Management

#### 1. Get All Users (with filters)
```
GET http://localhost:5000/api/users?page=1&per_page=20&role=admin&status=active&search=john
Authorization: Bearer {{access_token}}
```

#### 2. Create User
```
POST http://localhost:5000/api/users
Authorization: Bearer {{access_token}}
Content-Type: application/json

{
  "email": "newuser@example.com",
  "password": "Password123!",
  "role": "user",
  "status": "active",
  "first_name": "John",
  "last_name": "Doe",
  "application_ids": [1, 2]
}
```

#### 3. Get User by ID
```
GET http://localhost:5000/api/users/1
Authorization: Bearer {{access_token}}
```

#### 4. Update User
```
PUT http://localhost:5000/api/users/1
Authorization: Bearer {{access_token}}
Content-Type: application/json

{
  "first_name": "Updated",
  "last_name": "Name",
  "role": "admin"
}
```

#### 5. Delete User
```
DELETE http://localhost:5000/api/users/1
Authorization: Bearer {{access_token}}
```

---

### Application Management

#### 1. Get All Applications
```
GET http://localhost:5000/api/applications?page=1&per_page=10&status=active
Authorization: Bearer {{access_token}}
```

#### 2. Create Application
```
POST http://localhost:5000/api/applications
Authorization: Bearer {{access_token}}
Content-Type: application/json

{
  "name": "New Application",
  "description": "Application description",
  "url": "https://app.example.com",
  "status": "active"
}
```

#### 3. Get Application by ID
```
GET http://localhost:5000/api/applications/1
Authorization: Bearer {{access_token}}
```

#### 4. Update Application
```
PUT http://localhost:5000/api/applications/1
Authorization: Bearer {{access_token}}
Content-Type: application/json

{
  "status": "maintenance",
  "description": "Updated description"
}
```

#### 5. Delete Application
```
DELETE http://localhost:5000/api/applications/1
Authorization: Bearer {{access_token}}
```

---

### Dashboard

#### 1. Get Dashboard Stats
```
GET http://localhost:5000/api/dashboard/stats
Authorization: Bearer {{access_token}}
```

#### 2. Get System Health
```
GET http://localhost:5000/api/dashboard/health
Authorization: Bearer {{access_token}}
```

#### 3. Get Recent Activity
```
GET http://localhost:5000/api/dashboard/activity
Authorization: Bearer {{access_token}}
```

#### 4. Get Metrics History
```
GET http://localhost:5000/api/dashboard/metrics/history
Authorization: Bearer {{access_token}}
```

---

## Testing

### Run Tests
```bash
# Activate virtual environment
source venv/bin/activate

# Run all tests
pytest

# Run with coverage
pytest --cov=app

# Run specific test file
pytest tests/unit/test_user_model.py
```

### Test Structure
- `tests/unit/`: Unit tests for models and schemas
- `tests/integration/`: Integration tests for API endpoints

---

## Troubleshooting

### Common Issues

#### 1. Database Connection Error
**Error:** `sqlalchemy.exc.OperationalError: could not connect to server`

**Solution:**
- Verify PostgreSQL container is running: `docker ps`
- Check DATABASE_URL in `.env` file
- Verify database exists: `docker exec rag_postgres psql -U raguser -l`

#### 2. Authentication Error
**Error:** `401 Unauthorized`

**Solution:**
- Verify access token is valid
- Check token expiration (default: 1 hour)
- Use refresh token to get new access token

#### 3. Permission Denied
**Error:** `403 Forbidden - Admin access required`

**Solution:**
- Verify user has admin or superadmin role
- Check JWT token contains correct role claim

#### 4. Validation Error
**Error:** `400 Validation Error`

**Solution:**
- Check request body matches schema
- Verify required fields are provided
- Check data types match schema definitions

---

## Best Practices

### Security
1. **Never commit `.env` file** - Contains sensitive credentials
2. **Use strong secrets** - Generate random SECRET_KEY and JWT_SECRET_KEY
3. **HTTPS in production** - Always use HTTPS for production deployments
4. **Token expiration** - Access tokens expire in 1 hour (configurable)
5. **Password strength** - Enforce strong passwords (minimum 6 characters)

### API Usage
1. **Always handle errors** - Check response status codes
2. **Use pagination** - For large datasets, use pagination
3. **Refresh tokens** - Implement token refresh mechanism
4. **Rate limiting** - Consider implementing rate limiting
5. **Logging** - Monitor activity logs for security

### Development
1. **Environment variables** - Use `.env` for configuration
2. **Database migrations** - Use Flask-Migrate for schema changes
3. **Testing** - Write tests for new features
4. **Code style** - Follow PEP 8 guidelines
5. **Documentation** - Keep documentation updated

---

## Support

For issues or questions:
1. Check this documentation
2. Review error messages
3. Check application logs
4. Verify database connection
5. Test with Postman examples

---

## License

This project is provided as-is for educational and development purposes.

---

**Last Updated:** 2024-01-15
**Version:** 1.0.0

