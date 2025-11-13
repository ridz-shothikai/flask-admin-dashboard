# Postman Guide - Flask Admin Dashboard API

## Quick Start Guide

This guide provides step-by-step instructions for using the Flask Admin Dashboard API with Postman.

---

## Table of Contents
1. [Initial Setup](#initial-setup)
2. [Authentication Flow](#authentication-flow)
3. [Request Examples](#request-examples)
4. [Automation Scripts](#automation-scripts)
5. [Troubleshooting](#troubleshooting)

---

## Initial Setup

### Step 1: Create Postman Collection

1. Open Postman
2. Click **New** → **Collection**
3. Name it: **"Flask Admin Dashboard"**
4. Description: "Complete API collection for Flask Admin Dashboard"

### Step 2: Configure Collection Variables

1. Click on your collection
2. Go to **Variables** tab
3. Add the following variables:

| Variable | Initial Value | Current Value |
|----------|---------------|---------------|
| `base_url` | `http://localhost:5000/api` | `http://localhost:5000/api` |
| `access_token` | (leave empty) | (auto-set) |
| `refresh_token` | (leave empty) | (auto-set) |
| `user_id` | (leave empty) | (auto-set) |

### Step 3: Set Collection Authorization

1. Click on collection → **Authorization** tab
2. Type: **Bearer Token**
3. Token: `{{access_token}}`
4. This applies to all requests automatically

### Step 4: Create Folder Structure

Create these folders in your collection:
- 📁 **Authentication**
- 📁 **Users**
- 📁 **Applications**
- 📁 **Dashboard**

---

## Authentication Flow

### 1. Login Request

**Create Request:**
- Method: `POST`
- URL: `{{base_url}}/auth/login`
- Folder: **Authentication**

**Headers:**
```
Content-Type: application/json
```

**Body (raw JSON):**
```json
{
  "email": "admin@example.com",
  "password": "Admin123!"
}
```

**Tests Tab (Auto-save tokens):**
```javascript
// Check if login was successful
if (pm.response.code === 200) {
    const response = pm.response.json();
    
    // Save tokens to collection variables
    pm.collectionVariables.set("access_token", response.access_token);
    pm.collectionVariables.set("refresh_token", response.refresh_token);
    pm.collectionVariables.set("user_id", response.user.id);
    
    // Log success
    console.log("Login successful!");
    console.log("User ID:", response.user.id);
    console.log("User Role:", response.user.role);
} else {
    console.log("Login failed:", pm.response.json());
}
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
    "status": "active",
    "first_name": "John",
    "last_name": "Administrator",
    "created_date": "2024-01-01T00:00:00",
    "last_login": "2024-01-15T10:30:00",
    "assigned_applications": [...]
  }
}
```

### 2. Refresh Token Request

**Create Request:**
- Method: `POST`
- URL: `{{base_url}}/auth/refresh`
- Folder: **Authentication**

**Authorization:**
- Type: **Bearer Token**
- Token: `{{refresh_token}}`

**Tests Tab:**
```javascript
if (pm.response.code === 200) {
    const response = pm.response.json();
    pm.collectionVariables.set("access_token", response.access_token);
    console.log("Token refreshed successfully!");
}
```

### 3. Verify Token Request

**Create Request:**
- Method: `POST` or `GET`
- URL: `{{base_url}}/auth/verify`
- Folder: **Authentication**

**Option 1 - Using Authorization Header:**
- Authorization: Type **Bearer Token**
- Token: `{{access_token}}`

**Option 2 - Using Request Body (POST only):**
- Body → raw → JSON:
```json
{
  "token": "{{access_token}}"
}
```

**Option 3 - Using Query Parameter (GET only):**
- Params:
  - Key: `token`
  - Value: `{{access_token}}`

**Tests Tab:**
```javascript
if (pm.response.code === 200) {
    const response = pm.response.json();
    if (response.valid) {
        console.log("Token is valid!");
        console.log("User:", response.user.email);
        console.log("Role:", response.token_info.role);
        console.log("Expires at:", response.token_info.expires_at);
    } else {
        console.log("Token is invalid:", response.error.message);
    }
}
```

**Expected Response (Valid Token):**
```json
{
  "valid": true,
  "token_info": {
    "user_id": "1",
    "role": "admin",
    "token_type": "access",
    "expires_at": "2024-01-01T12:00:00",
    "issued_at": "2024-01-01T11:00:00"
  },
  "user": {
    "id": 1,
    "email": "admin@example.com",
    "role": "admin",
    "status": "active",
    ...
  }
}
```

**Expected Response (Invalid/Expired Token):**
```json
{
  "valid": false,
  "error": {
    "code": "TOKEN_EXPIRED",
    "message": "Token has expired"
  }
}
```

**Error Codes:**
- `TOKEN_MISSING`: Token not provided
- `TOKEN_EXPIRED`: Token has expired
- `INVALID_TOKEN`: Token is invalid or malformed
- `USER_NOT_FOUND`: User associated with token not found
- `ACCOUNT_INACTIVE`: User account is inactive

### 4. Get Current User

**Create Request:**
- Method: `GET`
- URL: `{{base_url}}/auth/me`
- Folder: **Authentication**

**Authorization:** Inherit from collection (uses `{{access_token}}`)

### 5. Logout

**Create Request:**
- Method: `POST`
- URL: `{{base_url}}/auth/logout`
- Folder: **Authentication**

**Authorization:** Inherit from collection

---

## Request Examples

### User Management

#### Get All Users

**Request:**
- Method: `GET`
- URL: `{{base_url}}/users?page=1&per_page=10&role=admin&status=active`
- Folder: **Users**

**Query Parameters:**
- `page`: 1
- `per_page`: 10
- `role`: admin (optional)
- `status`: active (optional)
- `search`: john (optional)
- `sort`: created_date (optional)
- `order`: desc (optional)

**Pre-request Script (Optional - Dynamic pagination):**
```javascript
// Set pagination variables
pm.collectionVariables.set("current_page", 1);
pm.collectionVariables.set("per_page", 10);
```

#### Create User

**Request:**
- Method: `POST`
- URL: `{{base_url}}/users`
- Folder: **Users**

**Body (raw JSON):**
```json
{
  "email": "newuser@example.com",
  "password": "Password123!",
  "role": "user",
  "status": "active",
  "first_name": "Jane",
  "last_name": "Doe",
  "application_ids": [1, 2]
}
```

**Tests Tab:**
```javascript
if (pm.response.code === 201) {
    const response = pm.response.json();
    console.log("User created:", response.user.email);
    pm.collectionVariables.set("last_created_user_id", response.user.id);
}
```

#### Get User by ID

**Request:**
- Method: `GET`
- URL: `{{base_url}}/users/{{user_id}}`
- Folder: **Users**

#### Get All Roles

**Request:**
- Method: `GET`
- URL: `{{base_url}}/users/roles`
- Folder: **Users**

**Description:** Get all available user roles for dropdowns and filters

**Expected Response:**
```json
{
  "roles": [
    {
      "value": "user",
      "label": "User"
    },
    {
      "value": "admin",
      "label": "Admin"
    },
    {
      "value": "superadmin",
      "label": "Super Admin"
    }
  ]
}
```

**Tests Tab:**
```javascript
if (pm.response.code === 200) {
    const response = pm.response.json();
    console.log("Available roles:", response.roles.length);
    pm.collectionVariables.set("available_roles", JSON.stringify(response.roles));
}
```

#### Update User

**Request:**
- Method: `PUT`
- URL: `{{base_url}}/users/{{user_id}}`
- Folder: **Users**

**Body (raw JSON - all fields optional):**
```json
{
  "first_name": "Updated",
  "last_name": "Name",
  "role": "admin",
  "status": "active",
  "application_ids": [1, 2, 3]
}
```

#### Delete User

**Request:**
- Method: `DELETE`
- URL: `{{base_url}}/users/{{user_id}}`
- Folder: **Users**

**Tests Tab:**
```javascript
if (pm.response.code === 200) {
    console.log("User deleted successfully");
}
```

---

### Application Management

#### Get All Applications

**Request:**
- Method: `GET`
- URL: `{{base_url}}/applications?page=1&per_page=10&status=active`
- Folder: **Applications**

**Query Parameters:**
- `page`: 1
- `per_page`: 10
- `search`: dashboard (optional)
- `status`: active (optional)
- `sort`: name (optional)
- `order`: asc (optional)

#### Create Application

**Request:**
- Method: `POST`
- URL: `{{base_url}}/applications`
- Folder: **Applications**

**Body (raw JSON):**
```json
{
  "name": "New Application",
  "description": "Application description here",
  "url": "https://app.example.com",
  "status": "active"
}
```

**Tests Tab:**
```javascript
if (pm.response.code === 201) {
    const response = pm.response.json();
    console.log("Application created:", response.application.name);
    pm.collectionVariables.set("last_created_app_id", response.application.id);
}
```

#### Get Application by ID

**Request:**
- Method: `GET`
- URL: `{{base_url}}/applications/1`
- Folder: **Applications**

#### Update Application

**Request:**
- Method: `PUT`
- URL: `{{base_url}}/applications/1`
- Folder: **Applications**

**Body (raw JSON - all fields optional):**
```json
{
  "name": "Updated Application Name",
  "description": "Updated description",
  "url": "https://updated.example.com",
  "status": "maintenance"
}
```

#### Delete Application

**Request:**
- Method: `DELETE`
- URL: `{{base_url}}/applications/1`
- Folder: **Applications**

---

### Dashboard

#### Get Dashboard Statistics

**Request:**
- Method: `GET`
- URL: `{{base_url}}/dashboard/stats`
- Folder: **Dashboard**

**Tests Tab:**
```javascript
if (pm.response.code === 200) {
    const stats = pm.response.json();
    console.log("Total users:", stats.users.total);
    console.log("Active users:", stats.users.active);
    console.log("Total applications:", stats.applications.total);
}
```

#### Get System Health

**Request:**
- Method: `GET`
- URL: `{{base_url}}/dashboard/health`
- Folder: **Dashboard**

**Tests Tab:**
```javascript
if (pm.response.code === 200) {
    const health = pm.response.json();
    console.log("CPU Usage:", health.cpu.usage_percent + "%");
    console.log("Memory Usage:", health.memory.usage_percent + "%");
    console.log("Disk Usage:", health.disk.usage_percent + "%");
}
```

#### Get Recent Activity

**Request:**
- Method: `GET`
- URL: `{{base_url}}/dashboard/activity`
- Folder: **Dashboard**

#### Get Metrics History

**Request:**
- Method: `GET`
- URL: `{{base_url}}/dashboard/metrics/history`
- Folder: **Dashboard**

---

## Automation Scripts

### Collection-Level Pre-request Script

Add this to your collection's **Pre-request Script** tab to automatically refresh tokens:

```javascript
// Check if access token is about to expire (optional)
// This is a simple check - you might want to decode JWT to check actual expiration
const accessToken = pm.collectionVariables.get("access_token");
const refreshToken = pm.collectionVariables.get("refresh_token");

// If no access token, try to login (optional auto-login)
if (!accessToken && refreshToken) {
    // Auto-refresh token
    pm.sendRequest({
        url: pm.collectionVariables.get("base_url") + "/auth/refresh",
        method: 'POST',
        header: {
            'Authorization': 'Bearer ' + refreshToken
        }
    }, function (err, res) {
        if (res.code === 200) {
            pm.collectionVariables.set("access_token", res.json().access_token);
        }
    });
}
```

### Collection-Level Tests Script

Add this to your collection's **Tests** tab for global error handling:

```javascript
// Global error handling
if (pm.response.code >= 400) {
    const error = pm.response.json();
    console.error("Error:", error.error.code, "-", error.error.message);
    
    // Handle token expiration
    if (pm.response.code === 401 && error.error.code === "UNAUTHORIZED") {
        console.log("Token may have expired. Please refresh or login again.");
    }
}
```

---

## Complete Postman Collection JSON

You can import this complete collection:

```json
{
  "info": {
    "name": "Flask Admin Dashboard",
    "description": "Complete API collection for Flask Admin Dashboard",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "variable": [
    {
      "key": "base_url",
      "value": "http://localhost:5000/api",
      "type": "string"
    },
    {
      "key": "access_token",
      "value": "",
      "type": "string"
    },
    {
      "key": "refresh_token",
      "value": "",
      "type": "string"
    }
  ],
  "auth": {
    "type": "bearer",
    "bearer": [
      {
        "key": "token",
        "value": "{{access_token}}",
        "type": "string"
      }
    ]
  }
}
```

---

## Troubleshooting

### Issue: 401 Unauthorized

**Problem:** Token expired or invalid

**Solution:**
1. Check if token is set: `{{access_token}}`
2. Try refreshing token: Use refresh endpoint
3. Re-login if refresh fails

### Issue: 403 Forbidden

**Problem:** Insufficient permissions

**Solution:**
1. Verify user role is admin or superadmin
2. Check JWT token contains correct role
3. Login with admin account

### Issue: 400 Validation Error

**Problem:** Invalid request data

**Solution:**
1. Check request body matches schema
2. Verify all required fields are present
3. Check data types (email format, string length, etc.)

### Issue: 500 Internal Server Error

**Problem:** Server error

**Solution:**
1. Check application logs
2. Verify database connection
3. Check if all required services are running

---

## Best Practices

1. **Always save tokens** - Use Tests tab to auto-save tokens
2. **Use variables** - Use `{{base_url}}` instead of hardcoded URLs
3. **Organize requests** - Use folders to organize by feature
4. **Add descriptions** - Document each request
5. **Use tests** - Add validation tests for responses
6. **Environment setup** - Create separate environments for dev/staging/prod

---

## Sample Test Data

After running `python scripts/seed_data.py`, you can use these credentials:

**Superadmin:**
- Email: `superadmin@example.com`
- Password: `SuperAdmin123!`

**Admin:**
- Email: `admin@example.com`
- Password: `Admin123!`

**Regular User:**
- Email: `user1@example.com`
- Password: `User123!`

---

## Quick Reference

### Base URL
```
http://localhost:5000/api
```

### Authentication Header
```
Authorization: Bearer {{access_token}}
```

### Common Status Codes
- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `409` - Conflict
- `500` - Internal Server Error

---

**Happy Testing! 🚀**
