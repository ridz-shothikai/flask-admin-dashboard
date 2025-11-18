# NextAuth.js Integration Guide for Flask SAML Backend

## Overview

Your Flask backend handles the complete SAML authentication flow with Okta. After successful authentication, it redirects to your Next.js frontend with a JWT token. Your frontend needs to:

1. Receive the JWT token from the callback URL
2. Validate and store it
3. Use it for authenticated API requests to the Flask backend

---

## Backend Flow (Already Complete)

```
User clicks "Login with SSO"
    ↓
Frontend redirects to: http://localhost:5000/api/auth/saml/login
    ↓
Flask redirects to Okta login
    ↓
User authenticates with Okta
    ↓
Okta redirects back to Flask: http://localhost:5000/api/auth/saml/acs
    ↓
Flask validates SAML response, creates JWT token
    ↓
Flask redirects to: http://localhost:3000/auth/saml-callback?token=JWT_TOKEN
    ↓
Frontend receives token (THIS IS WHERE YOU START)
```

---

## Frontend Implementation Options

You have **two main approaches** for integrating with NextAuth.js:

### Option A: Custom Provider (Recommended)
Use NextAuth's Credentials provider with a custom flow

### Option B: Pure Client-Side (Simpler)
Handle SAML callback without NextAuth, use token directly

---

## Option A: NextAuth.js with Custom Credentials Provider

### Step 1: Install Dependencies

```bash
npm install next-auth
# or
yarn add next-auth
```

### Step 2: Create NextAuth Configuration

Create `app/api/auth/[...nextauth]/route.ts` (App Router) or `pages/api/auth/[...nextauth].ts` (Pages Router):

```typescript
// app/api/auth/[...nextauth]/route.ts (for App Router)
import NextAuth, { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";

export const authOptions: NextAuthOptions = {
  providers: [
    CredentialsProvider({
      id: "saml-sso",
      name: "SAML SSO",
      credentials: {
        token: { label: "Token", type: "text" }
      },
      async authorize(credentials) {
        if (!credentials?.token) {
          return null;
        }

        try {
          // Verify the token with your Flask backend
          const response = await fetch('http://localhost:5000/api/auth/verify', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${credentials.token}`
            }
          });

          if (!response.ok) {
            return null;
          }

          const user = await response.json();

          // Return user object
          return {
            id: user.id,
            email: user.email,
            name: `${user.first_name} ${user.last_name}`,
            accessToken: credentials.token
          };
        } catch (error) {
          console.error('Token verification failed:', error);
          return null;
        }
      }
    })
  ],
  callbacks: {
    async jwt({ token, user }) {
      // Add access token to JWT token
      if (user) {
        token.accessToken = user.accessToken;
        token.id = user.id;
      }
      return token;
    },
    async session({ session, token }) {
      // Add access token to session
      session.accessToken = token.accessToken;
      session.user.id = token.id;
      return session;
    }
  },
  pages: {
    signIn: '/login',
  },
  session: {
    strategy: 'jwt'
  }
};

const handler = NextAuth(authOptions);
export { handler as GET, handler as POST };
```

### Step 3: Create SAML Callback Handler

Create `app/auth/saml-callback/page.tsx` (App Router):

```typescript
'use client';

import { useEffect } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { signIn } from 'next-auth/react';

export default function SAMLCallbackPage() {
  const router = useRouter();
  const searchParams = useSearchParams();

  useEffect(() => {
    const handleCallback = async () => {
      const token = searchParams.get('token');
      
      if (!token) {
        console.error('No token received from SAML');
        router.push('/login?error=no-token');
        return;
      }

      try {
        // Sign in with the token using NextAuth
        const result = await signIn('saml-sso', {
          token,
          redirect: false
        });

        if (result?.error) {
          console.error('Sign in error:', result.error);
          router.push('/login?error=auth-failed');
        } else {
          // Success! Redirect to dashboard or home
          router.push('/dashboard');
        }
      } catch (error) {
        console.error('Callback error:', error);
        router.push('/login?error=callback-failed');
      }
    };

    handleCallback();
  }, [searchParams, router]);

  return (
    <div className="flex items-center justify-center min-h-screen">
      <div className="text-center">
        <h2 className="text-xl font-semibold mb-2">Completing sign in...</h2>
        <p className="text-gray-600">Please wait while we verify your credentials.</p>
      </div>
    </div>
  );
}
```

Or for Pages Router (`pages/auth/saml-callback.tsx`):

```typescript
import { useEffect } from 'react';
import { useRouter } from 'next/router';
import { signIn } from 'next-auth/react';

export default function SAMLCallbackPage() {
  const router = useRouter();
  const { token } = router.query;

  useEffect(() => {
    if (token && typeof token === 'string') {
      handleCallback(token);
    }
  }, [token]);

  const handleCallback = async (token: string) => {
    try {
      const result = await signIn('saml-sso', {
        token,
        redirect: false
      });

      if (result?.error) {
        console.error('Sign in error:', result.error);
        router.push('/login?error=auth-failed');
      } else {
        router.push('/dashboard');
      }
    } catch (error) {
      console.error('Callback error:', error);
      router.push('/login?error=callback-failed');
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen">
      <div className="text-center">
        <h2 className="text-xl font-semibold mb-2">Completing sign in...</h2>
        <p className="text-gray-600">Please wait while we verify your credentials.</p>
      </div>
    </div>
  );
}
```

### Step 4: Create Login Page with SSO Button

```typescript
'use client';

import { signIn } from 'next-auth/react';

export default function LoginPage() {
  const handleSSOLogin = () => {
    // Redirect to Flask SAML login endpoint
    window.location.href = 'http://localhost:5000/api/auth/saml/login';
  };

  return (
    <div className="flex items-center justify-center min-h-screen">
      <div className="w-full max-w-md p-8 space-y-6 bg-white rounded-lg shadow">
        <h1 className="text-2xl font-bold text-center">Sign In</h1>
        
        <button
          onClick={handleSSOLogin}
          className="w-full px-4 py-2 text-white bg-blue-600 rounded hover:bg-blue-700"
        >
          Sign in with SSO
        </button>
      </div>
    </div>
  );
}
```

### Step 5: Protect Routes with NextAuth

```typescript
// For App Router - middleware.ts
export { default } from "next-auth/middleware";

export const config = {
  matcher: ['/dashboard/:path*', '/profile/:path*']
};
```

### Step 6: Use Session in Components

```typescript
'use client';

import { useSession, signOut } from 'next-auth/react';

export default function Dashboard() {
  const { data: session, status } = useSession();

  if (status === 'loading') {
    return <div>Loading...</div>;
  }

  if (!session) {
    return <div>Access Denied</div>;
  }

  return (
    <div>
      <h1>Welcome, {session.user?.name}</h1>
      <p>Email: {session.user?.email}</p>
      <button onClick={() => signOut()}>Sign Out</button>
    </div>
  );
}
```

### Step 7: Make API Calls to Flask Backend

```typescript
import { useSession } from 'next-auth/react';

export default function MyComponent() {
  const { data: session } = useSession();

  const fetchData = async () => {
    if (!session?.accessToken) return;

    const response = await fetch('http://localhost:5000/api/your-endpoint', {
      headers: {
        'Authorization': `Bearer ${session.accessToken}`,
        'Content-Type': 'application/json'
      }
    });

    const data = await response.json();
    return data;
  };

  // Use fetchData as needed
}
```

---

## Option B: Client-Side Token Management (Without NextAuth)

If you want a simpler approach without NextAuth:

### Step 1: Create SAML Callback Handler

```typescript
'use client';

import { useEffect } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';

export default function SAMLCallbackPage() {
  const router = useRouter();
  const searchParams = useSearchParams();

  useEffect(() => {
    const token = searchParams.get('token');
    
    if (token) {
      // Store token in localStorage or cookie
      localStorage.setItem('auth_token', token);
      
      // Optionally verify token with backend
      verifyToken(token).then(isValid => {
        if (isValid) {
          router.push('/dashboard');
        } else {
          router.push('/login?error=invalid-token');
        }
      });
    } else {
      router.push('/login?error=no-token');
    }
  }, [searchParams, router]);

  const verifyToken = async (token: string): Promise<boolean> => {
    try {
      const response = await fetch('http://localhost:5000/api/auth/verify', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });
      return response.ok;
    } catch {
      return false;
    }
  };

  return <div>Completing sign in...</div>;
}
```

### Step 2: Create Auth Context

```typescript
'use client';

import { createContext, useContext, useState, useEffect } from 'react';

interface AuthContextType {
  token: string | null;
  user: any;
  login: (token: string) => void;
  logout: () => void;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState(null);

  useEffect(() => {
    // Load token from localStorage on mount
    const storedToken = localStorage.getItem('auth_token');
    if (storedToken) {
      setToken(storedToken);
      fetchUser(storedToken);
    }
  }, []);

  const fetchUser = async (token: string) => {
    try {
      const response = await fetch('http://localhost:5000/api/auth/me', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (response.ok) {
        const userData = await response.json();
        setUser(userData);
      }
    } catch (error) {
      console.error('Failed to fetch user:', error);
    }
  };

  const login = (newToken: string) => {
    localStorage.setItem('auth_token', newToken);
    setToken(newToken);
    fetchUser(newToken);
  };

  const logout = () => {
    localStorage.removeItem('auth_token');
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{
      token,
      user,
      login,
      logout,
      isAuthenticated: !!token
    }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};
```

### Step 3: Use Auth Context

```typescript
'use client';

import { useAuth } from '@/contexts/AuthContext';

export default function Dashboard() {
  const { user, logout, isAuthenticated } = useAuth();

  if (!isAuthenticated) {
    return <div>Please login</div>;
  }

  return (
    <div>
      <h1>Welcome, {user?.first_name}</h1>
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

---

## Backend Requirements (For You)

Your frontend developer will need these Flask endpoints:

### 1. Token Verification Endpoint (Required for Option A)

```python
@auth_bp.route('/verify', methods=['POST'])
@jwt_required()
def verify_token():
    """Verify JWT token and return user info"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'id': user.id,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name
    }), 200
```

### 2. Get Current User Endpoint (Optional but useful)

```python
@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current authenticated user"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'id': user.id,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name
    }), 200
```

### 3. CORS Configuration (Important!)

Make sure your Flask app allows requests from the Next.js frontend:

```python
from flask_cors import CORS

CORS(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:3000", "https://yourdomain.com"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})
```

---

## Environment Variables

### Backend (.env)
```bash
SAML_ENABLED=true
SAML_SP_BASE_URL=http://localhost:5000
SAML_SP_ENTITY_ID=http://localhost:5000/api/auth/saml/metadata
SAML_IDP_ENTITY_ID=http://www.okta.com/exk...
SAML_IDP_SSO_URL=https://trial-3903544.okta.com/app/.../sso/saml
SAML_IDP_X509_CERT=MIIDpDCCAoyg...
FRONTEND_URL=http://localhost:3000
SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret-key
```

### Frontend (.env.local)
```bash
NEXT_PUBLIC_API_URL=http://localhost:5000
NEXTAUTH_URL=http://localhost:3000
NEXTAUTH_SECRET=your-nextauth-secret
```

---

## Testing the Integration

### 1. Start Both Servers
```bash
# Backend (Flask)
python run.py

# Frontend (Next.js)
npm run dev
```

### 2. Test Flow
1. Go to `http://localhost:3000/login`
2. Click "Sign in with SSO"
3. Redirects to Flask → Okta → Flask → Next.js
4. Should land on dashboard with session

### 3. Verify Token
- Check browser developer tools → Application → Local Storage or Cookies
- Token should be stored
- Try protected routes

---

## Troubleshooting

### Issue: CORS errors
**Solution**: Add CORS middleware to Flask (see Backend Requirements)

### Issue: Token not received in callback
**Solution**: Check FRONTEND_URL in Flask .env matches Next.js URL

### Issue: NextAuth session not created
**Solution**: Verify token verification endpoint returns correct user data

### Issue: Redirect loop
**Solution**: Check that callback page doesn't require authentication

---

## Production Considerations

1. **Environment URLs**: Update all localhost URLs to production domains
2. **HTTPS**: Use HTTPS for all endpoints in production
3. **Secure Cookies**: Enable secure cookies for NextAuth in production
4. **Token Expiration**: Handle JWT token expiration and refresh
5. **Error Handling**: Add comprehensive error handling and logging
6. **Security Headers**: Add security headers to both backend and frontend

---

## Summary for Frontend Developer

**What you need to do:**

1. ✅ Install NextAuth.js (if using Option A)
2. ✅ Create `/auth/saml-callback` page to receive token
3. ✅ Store token in NextAuth session or localStorage
4. ✅ Create login page with SSO button that redirects to Flask
5. ✅ Use token in Authorization header for all API calls to Flask
6. ✅ Handle token expiration and errors

**Backend provides:**
- ✅ Complete SAML authentication with Okta
- ✅ JWT token generation
- ✅ Token verification endpoint
- ✅ User data endpoint

**The backend developer should provide you with:**
- Flask API base URL
- Token verification endpoint
- User data endpoint
- CORS configuration confirmation

Good luck with the integration! 🚀
