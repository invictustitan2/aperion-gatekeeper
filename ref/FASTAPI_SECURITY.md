# FastAPI Security Best Practices

> Patterns for secure FastAPI authentication and authorization
> Last Updated: 2026-02-08

## Authentication Patterns

### 1. OAuth2 with JWT

**Standard FastAPI Pattern:**

```python
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta

# Configuration
SECRET_KEY = os.environ["JWT_SECRET_KEY"]  # Never hardcode!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user
```

**Gatekeeper Enhancement:** Add JWT support to `AuthenticationEngine`

---

### 2. RBAC with Dependencies

**Centralized Role Check:**

```python
from functools import wraps
from typing import Callable

def require_roles(*required_roles: str) -> Callable:
    """Dependency factory for role-based access control."""
    
    async def role_checker(
        current_user: User = Depends(get_current_user)
    ) -> User:
        if not any(role in current_user.roles for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of: {required_roles}"
            )
        return current_user
    
    return role_checker

# Usage
@app.get("/admin/users")
async def list_users(user: User = Depends(require_roles("admin", "superadmin"))):
    return await get_all_users()
```

**Status in Gatekeeper:** ✅ `require_role()` implemented in middleware

---

### 3. Permission-Based Access

**More Granular Than Roles:**

```python
class Permission(str, Enum):
    READ_USERS = "users:read"
    WRITE_USERS = "users:write"
    DELETE_USERS = "users:delete"
    ADMIN = "admin:*"

def require_permission(permission: Permission) -> Callable:
    async def permission_checker(
        current_user: User = Depends(get_current_user)
    ) -> User:
        if not has_permission(current_user, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission: {permission.value}"
            )
        return current_user
    
    return permission_checker
```

**Status in Gatekeeper:** ✅ `require_permission()` implemented

---

## Security Headers

### 1. CORS Configuration

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://trusted-domain.com"],  # Never use ["*"] in production
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
```

### 2. Security Headers Middleware

```python
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response

app.add_middleware(SecurityHeadersMiddleware)
```

---

## Rate Limiting

### Using slowapi:

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, credentials: LoginCredentials):
    ...
```

**Status in Gatekeeper:** ❌ No rate limiting (see GAP_ANALYSIS.md #2)

---

## Input Validation

### Pydantic Models:

```python
from pydantic import BaseModel, Field, EmailStr, validator

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=12)
    
    @validator("username")
    def username_alphanumeric(cls, v):
        if not v.isalnum():
            raise ValueError("Username must be alphanumeric")
        return v
    
    @validator("password")
    def password_strength(cls, v):
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain uppercase")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain digit")
        return v
```

---

## Error Handling

### Don't Leak Internal Details:

```python
from fastapi import Request
from fastapi.responses import JSONResponse

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Log full details internally
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    
    # Return generic message to client
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred"}
    )
```

---

## Logging Best Practices

### Structured Logging with Correlation:

```python
import structlog
from uuid import uuid4

def configure_logging():
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ]
    )

@app.middleware("http")
async def add_correlation_id(request: Request, call_next):
    correlation_id = request.headers.get("X-Correlation-ID", str(uuid4()))
    
    # Bind to context
    structlog.contextvars.bind_contextvars(correlation_id=correlation_id)
    
    response = await call_next(request)
    response.headers["X-Correlation-ID"] = correlation_id
    return response
```

**Status in Gatekeeper:** ⚠️ Correlation ID support exists but not integrated

---

## Production Checklist

- [ ] HTTPS enforced (redirect HTTP → HTTPS)
- [ ] Security headers configured
- [ ] CORS properly restricted
- [ ] Rate limiting enabled
- [ ] Input validation on all endpoints
- [ ] Error messages don't leak internals
- [ ] Structured logging with correlation IDs
- [ ] Secrets from environment/vault (never in code)
- [ ] Dependencies audited (`pip-audit`)
- [ ] Authentication required on all non-public routes

---

## References

- [FastAPI Security Documentation](https://fastapi.tiangolo.com/tutorial/security/)
- [Better Stack: Authentication with FastAPI](https://betterstack.com/community/guides/scaling-python/authentication-fastapi/)
- [FastAPI Best Practices](https://deepwiki.com/fastapi-practices/fastapi_best_architecture/)
