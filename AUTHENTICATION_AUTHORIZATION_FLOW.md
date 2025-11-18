# Authentication & Authorization Flow Diagrams

This document provides comprehensive flowcharts showing how authentication and authorization work in the Flask Admin Dashboard.

## Table of Contents
1. [Password-Based Authentication Flow](#1-password-based-authentication-flow)
2. [SAML SSO Authentication Flow](#2-saml-sso-authentication-flow)
3. [JWT Token Refresh Flow](#3-jwt-token-refresh-flow)
4. [Authorization & Role-Based Access Control](#4-authorization--role-based-access-control)
5. [Protected Route Access Flow](#5-protected-route-access-flow)
6. [Complete Authentication Architecture](#6-complete-authentication-architecture)

---

## 1. Password-Based Authentication Flow

```mermaid
sequenceDiagram
    participant Client
    participant Flask API
    participant Database
    participant JWT Manager
    participant Activity Logger

    Client->>Flask API: POST /api/auth/login<br/>{email, password}
    
    Flask API->>Database: Query User by email
    Database-->>Flask API: User record
    
    alt User not found OR password invalid
        Flask API-->>Client: 401 Unauthorized<br/>{error: "INVALID_CREDENTIALS"}
    else User found AND password valid
        alt User status != 'active'
            Flask API-->>Client: 403 Forbidden<br/>{error: "ACCOUNT_INACTIVE"}
        else User is active
            Flask API->>Database: Update last_login timestamp
            Flask API->>JWT Manager: create_access_token(user_id, role)
            JWT Manager-->>Flask API: access_token
            Flask API->>JWT Manager: create_refresh_token(user_id)
            JWT Manager-->>Flask API: refresh_token
            Flask API->>Activity Logger: Log "user_login" event
            Activity Logger->>Database: Save activity log
            Flask API-->>Client: 200 OK<br/>{access_token, refresh_token, user}
        end
    end
```

---

## 2. SAML SSO Authentication Flow

```mermaid
sequenceDiagram
    participant User Browser
    participant Flask API (SP)
    participant SAML Library
    participant Identity Provider (IdP)
    participant Database
    participant JWT Manager
    participant Frontend

    User Browser->>Flask API: GET /api/auth/saml/login
    
    Flask API->>SAML Library: Initialize SAML Auth
    SAML Library->>SAML Library: Generate SAML Request
    Flask API-->>User Browser: 302 Redirect to IdP SSO URL
    
    User Browser->>Identity Provider: SAML Authentication Request
    Identity Provider->>User Browser: Show login form
    User Browser->>Identity Provider: Submit credentials
    Identity Provider->>Identity Provider: Validate credentials
    
    alt Authentication failed
        Identity Provider-->>User Browser: Authentication error
    else Authentication successful
        Identity Provider->>Identity Provider: Generate SAML Response<br/>(signed assertion)
        Identity Provider-->>User Browser: 302 Redirect to ACS<br/>(POST with SAMLResponse)
        
        User Browser->>Flask API: POST /api/auth/saml/acs<br/>{SAMLResponse}
        
        Flask API->>SAML Library: Process SAML Response
        SAML Library->>SAML Library: Validate signature<br/>Verify certificate<br/>Check timestamps
        
        alt SAML validation failed
            SAML Library-->>Flask API: Validation errors
            Flask API-->>Frontend: Redirect to /auth/error
        else SAML validation successful
            SAML Library->>SAML Library: Check is_authenticated()
            
            alt User not authenticated
                Flask API-->>Frontend: Redirect to /auth/error
            else User authenticated
                SAML Library->>Flask API: Extract email from NameID/Attributes
                Flask API->>Database: Query User by email
                
                alt User not found
                    Flask API->>Database: Auto-provision new SSO user<br/>(role: SAML_DEFAULT_ROLE)
                    Database-->>Flask API: New user created
                end
                
                Flask API->>Database: Update last_login<br/>Set is_sso_user=True
                Flask API->>JWT Manager: create_access_token(user_id, role)
                JWT Manager-->>Flask API: access_token
                Flask API->>Database: Log "saml_login" activity
                Flask API-->>Frontend: 302 Redirect to /auth/saml-callback?token={access_token}
                
                Frontend->>Frontend: Store token in localStorage/session
                Frontend-->>User Browser: Display dashboard
            end
        end
    end
```

---

## 3. JWT Token Refresh Flow

```mermaid
sequenceDiagram
    participant Client
    participant Flask API
    participant JWT Manager
    participant Database

    Client->>Flask API: POST /api/auth/refresh<br/>Authorization: Bearer {refresh_token}
    
    Flask API->>JWT Manager: Validate refresh token
    JWT Manager->>JWT Manager: Verify signature<br/>Check expiration
    
    alt Token invalid or expired
        JWT Manager-->>Flask API: Token validation failed
        Flask API-->>Client: 401 Unauthorized
    else Token valid
        JWT Manager->>Flask API: Extract user_id from token
        Flask API->>Database: Query User by ID (optional validation)
        Database-->>Flask API: User record
        
        Flask API->>JWT Manager: create_access_token(user_id, role)
        JWT Manager-->>Flask API: New access_token
        Flask API-->>Client: 200 OK<br/>{access_token}
    end
```

---

## 4. Authorization & Role-Based Access Control

```mermaid
flowchart TD
    Start([Client Request]) --> CheckToken{Has JWT Token?}
    
    CheckToken -->|No| Reject1[401 Unauthorized]
    CheckToken -->|Yes| ValidateToken[Validate JWT Token]
    
    ValidateToken --> TokenValid{Token Valid?}
    TokenValid -->|No| Reject2[401 Unauthorized]
    TokenValid -->|Yes| ExtractClaims[Extract JWT Claims<br/>user_id, role]
    
    ExtractClaims --> CheckRoute{Route Requires<br/>Admin?}
    
    CheckRoute -->|No| AllowAccess[Allow Access<br/>Return Data]
    CheckRoute -->|Yes| CheckRole{User Role?}
    
    CheckRole -->|user| Reject3[403 Forbidden<br/>Admin access required]
    CheckRole -->|admin| AllowAccess
    CheckRole -->|superadmin| AllowAccess
    
    AllowAccess --> End([Request Processed])
    Reject1 --> End
    Reject2 --> End
    Reject3 --> End
    
    style Reject1 fill:#ffcccc
    style Reject2 fill:#ffcccc
    style Reject3 fill:#ffcccc
    style AllowAccess fill:#ccffcc
```

### Role Hierarchy

```
┌─────────────────────────────────────────┐
│         superadmin                      │
│  (Highest privileges - all access)     │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│         admin                           │
│  (User management, application mgmt)  │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│         user                            │
│  (Basic access - view own data)         │
└─────────────────────────────────────────┘
```

### Role Permissions Matrix

| Endpoint | user | admin | superadmin |
|----------|------|-------|------------|
| `GET /api/users` | ❌ | ✅ | ✅ |
| `POST /api/users` | ❌ | ✅ | ✅ |
| `PUT /api/users/:id` | ❌ | ✅ | ✅ |
| `DELETE /api/users/:id` | ❌ | ✅ | ✅ |
| `GET /api/applications` | ✅ | ✅ | ✅ |
| `POST /api/applications` | ❌ | ✅ | ✅ |
| `GET /api/dashboard/stats` | ✅ | ✅ | ✅ |
| `GET /api/auth/me` | ✅ | ✅ | ✅ |

---

## 5. Protected Route Access Flow

```mermaid
sequenceDiagram
    participant Client
    participant Flask Middleware
    participant JWT Manager
    participant Route Handler
    participant Database
    participant Activity Logger

    Client->>Flask Middleware: GET /api/users<br/>Authorization: Bearer {access_token}
    
    Flask Middleware->>JWT Manager: @jwt_required() decorator
    JWT Manager->>JWT Manager: Extract token from header
    JWT Manager->>JWT Manager: Verify signature<br/>Check expiration
    
    alt Token invalid
        JWT Manager-->>Client: 401 Unauthorized
    else Token valid
        JWT Manager->>JWT Manager: Extract claims (user_id, role)
        JWT Manager->>Route Handler: Pass control with user context
        
        Route Handler->>Route Handler: @require_admin() check
        Route Handler->>Route Handler: get_jwt() to get role
        
        alt Role not admin/superadmin
            Route Handler-->>Client: 403 Forbidden
        else Role is admin/superadmin
            Route Handler->>Database: Query users with filters
            Database-->>Route Handler: User records
            Route Handler->>Route Handler: Format response
            Route Handler->>Activity Logger: Log activity (optional)
            Route Handler-->>Client: 200 OK<br/>{users: [...], pagination: {...}}
        end
    end
```

---

## 6. Complete Authentication Architecture

```mermaid
graph TB
    subgraph "Client Layer"
        WebApp[Web Application<br/>Frontend]
        MobileApp[Mobile App]
    end
    
    subgraph "API Gateway / Flask Application"
        AuthRoutes[Auth Routes<br/>/api/auth/*]
        UserRoutes[User Routes<br/>/api/users/*]
        AppRoutes[Application Routes<br/>/api/applications/*]
        DashboardRoutes[Dashboard Routes<br/>/api/dashboard/*]
    end
    
    subgraph "Authentication Methods"
        PasswordAuth[Password Authentication<br/>POST /api/auth/login]
        SAMLAuth[SAML SSO<br/>GET /api/auth/saml/login]
        TokenRefresh[Token Refresh<br/>POST /api/auth/refresh]
    end
    
    subgraph "Authorization Layer"
        JWTMiddleware[JWT Middleware<br/>@jwt_required]
        RoleChecker[Role Checker<br/>@require_admin]
    end
    
    subgraph "External Services"
        IdP[Identity Provider<br/>Okta/Azure AD/etc]
        SAMLLib[python3-saml Library]
    end
    
    subgraph "Data Layer"
        PostgreSQL[(PostgreSQL Database)]
        UserModel[User Model]
        ActivityModel[ActivityLog Model]
    end
    
    subgraph "Security Components"
        Bcrypt[Bcrypt<br/>Password Hashing]
        JWTManager[JWT Manager<br/>Token Generation]
    end
    
    WebApp --> AuthRoutes
    MobileApp --> AuthRoutes
    
    AuthRoutes --> PasswordAuth
    AuthRoutes --> SAMLAuth
    AuthRoutes --> TokenRefresh
    
    PasswordAuth --> UserModel
    PasswordAuth --> Bcrypt
    PasswordAuth --> JWTManager
    
    SAMLAuth --> SAMLLib
    SAMLLib --> IdP
    SAMLLib --> UserModel
    SAMLLib --> JWTManager
    
    TokenRefresh --> JWTManager
    
    UserRoutes --> JWTMiddleware
    AppRoutes --> JWTMiddleware
    DashboardRoutes --> JWTMiddleware
    
    JWTMiddleware --> JWTManager
    JWTMiddleware --> RoleChecker
    
    RoleChecker --> UserRoutes
    RoleChecker --> AppRoutes
    
    UserModel --> PostgreSQL
    ActivityModel --> PostgreSQL
    
    JWTManager --> UserModel
    
    style PasswordAuth fill:#e1f5ff
    style SAMLAuth fill:#e1f5ff
    style JWTMiddleware fill:#fff4e1
    style RoleChecker fill:#fff4e1
    style PostgreSQL fill:#e8f5e9
    style JWTManager fill:#fce4ec
```

---

## 7. Detailed SAML SSO Flow (Step-by-Step)

```mermaid
flowchart TD
    Start([User clicks<br/>SAML Login]) --> InitSAML[1. Initialize SAML Auth<br/>Load settings from config]
    
    InitSAML --> CheckEnabled{SAML_ENABLED?}
    CheckEnabled -->|No| Error1[Return Error:<br/>SAML_DISABLED]
    CheckEnabled -->|Yes| GenerateRequest[2. Generate SAML AuthnRequest<br/>Sign if required]
    
    GenerateRequest --> RedirectIdP[3. Redirect to IdP SSO URL<br/>302 Redirect]
    
    RedirectIdP --> IdPLogin[4. User authenticates<br/>at IdP]
    
    IdPLogin --> IdPValidate{IdP validates<br/>credentials?}
    IdPValidate -->|No| IdPError[IdP returns error]
    IdPValidate -->|Yes| IdPResponse[5. IdP generates<br/>SAML Response<br/>Signed assertion]
    
    IdPResponse --> PostACS[6. POST to ACS endpoint<br/>/api/auth/saml/acs<br/>with SAMLResponse]
    
    PostACS --> ValidateResponse[7. Validate SAML Response<br/>auth.process_response]
    
    ValidateResponse --> CheckSignature{Signature<br/>Valid?}
    CheckSignature -->|No| Error2[Redirect to<br/>/auth/error]
    CheckSignature -->|Yes| CheckTimestamp{Timestamp<br/>Valid?}
    
    CheckTimestamp -->|No| Error2
    CheckTimestamp -->|Yes| CheckAuth{auth.is_authenticated?}
    
    CheckAuth -->|No| Error2
    CheckAuth -->|Yes| ExtractEmail[8. Extract email<br/>from NameID/Attributes]
    
    ExtractEmail --> FindUser[9. Query database<br/>for user by email]
    
    FindUser --> UserExists{User<br/>exists?}
    UserExists -->|No| AutoProvision[10. Auto-provision user<br/>Create with SAML_DEFAULT_ROLE]
    UserExists -->|Yes| CheckStatus{User<br/>active?}
    AutoProvision --> CheckStatus
    
    CheckStatus -->|No| Error3[Redirect to<br/>/auth/error:<br/>Account inactive]
    CheckStatus -->|Yes| UpdateUser[11. Update user<br/>last_login, is_sso_user]
    
    UpdateUser --> GenerateJWT[12. Generate JWT<br/>access_token]
    
    GenerateJWT --> LogActivity[13. Log activity<br/>saml_login event]
    
    LogActivity --> RedirectFrontend[14. Redirect to frontend<br/>/auth/saml-callback?token=...]
    
    RedirectFrontend --> End([User authenticated<br/>Token stored])
    
    Error1 --> End
    IdPError --> End
    Error2 --> End
    Error3 --> End
    
    style ValidateResponse fill:#fff4e1
    style CheckSignature fill:#fff4e1
    style CheckAuth fill:#fff4e1
    style GenerateJWT fill:#e8f5e9
    style Error2 fill:#ffcccc
    style Error3 fill:#ffcccc
```

---

## 8. Token Lifecycle

```mermaid
stateDiagram-v2
    [*] --> NoToken: Initial State
    
    NoToken --> LoginAttempt: User attempts login
    LoginAttempt --> TokenIssued: Authentication successful
    
    TokenIssued --> TokenValid: Token in use
    TokenValid --> TokenExpiring: Nearing expiration
    TokenExpiring --> TokenRefresh: Refresh token used
    TokenRefresh --> TokenIssued: New token issued
    
    TokenValid --> TokenExpired: Expiration time reached
    TokenExpired --> ReLogin: User must re-authenticate
    ReLogin --> TokenIssued: New login successful
    
    TokenValid --> TokenRevoked: Logout called
    TokenRevoked --> [*]: Session ended
    
    TokenExpired --> [*]
    ReLogin --> [*]: Login failed
    
    note right of TokenIssued
        Access Token: 1 hour
        Refresh Token: 30 days
    end note
    
    note right of TokenRefresh
        New access token issued
        Refresh token remains valid
    end note
```

---

## 9. Security Validation Points

```mermaid
flowchart LR
    subgraph "Password Authentication Security"
        P1[1. Email validation] --> P2[2. Password strength check]
        P2 --> P3[3. Bcrypt hash verification]
        P3 --> P4[4. User status check]
        P4 --> P5[5. Activity logging]
    end
    
    subgraph "SAML Authentication Security"
        S1[1. SAML response signature validation] --> S2[2. Certificate verification]
        S2 --> S3[3. Timestamp validation]
        S3 --> S4[4. Assertion signature check]
        S4 --> S5[5. User authentication status]
        S5 --> S6[6. Email extraction & validation]
        S6 --> S7[7. User status check]
        S7 --> S8[8. Activity logging]
    end
    
    subgraph "JWT Token Security"
        J1[1. Token signature verification] --> J2[2. Expiration check]
        J2 --> J3[3. Token type validation]
        J3 --> J4[4. Claims extraction]
        J4 --> J5[5. Role verification]
    end
    
    style P3 fill:#fff4e1
    style S1 fill:#fff4e1
    style S2 fill:#fff4e1
    style J1 fill:#fff4e1
    style J2 fill:#fff4e1
```

---

## Key Components Summary

### Authentication Endpoints
- `POST /api/auth/login` - Password-based login
- `GET /api/auth/saml/login` - Initiate SAML SSO
- `POST /api/auth/saml/acs` - SAML Assertion Consumer Service
- `GET /api/auth/saml/metadata` - SAML SP metadata
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/logout` - Logout user
- `GET /api/auth/me` - Get current user

### Authorization Decorators
- `@jwt_required()` - Requires valid JWT token
- `@jwt_required(refresh=True)` - Requires refresh token
- `@require_admin()` - Requires admin or superadmin role
- `@validate_json_body(Schema)` - Validates request body
- `@validate_query_params(Schema)` - Validates query parameters

### Security Features
- ✅ Password hashing with bcrypt
- ✅ JWT token-based authentication
- ✅ SAML 2.0 SSO with signature validation
- ✅ Role-based access control (RBAC)
- ✅ Activity logging for audit trail
- ✅ Token expiration and refresh mechanism
- ✅ Auto-provisioning for SSO users
- ✅ Secure session management

---

## Notes

1. **SAML Security**: All SAML responses are cryptographically validated before processing
2. **Token Storage**: Frontend should store tokens securely (httpOnly cookies recommended for production)
3. **Auto-provisioning**: New SSO users are automatically created with `SAML_DEFAULT_ROLE` (default: 'user')
4. **Password vs SSO**: Users can have either password-based or SSO authentication, or both
5. **Role Hierarchy**: superadmin > admin > user (each level has all permissions of lower levels)

