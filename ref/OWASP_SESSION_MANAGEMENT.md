# OWASP Session Management Guidelines

> Source: OWASP Cheat Sheet Series
> Last Updated: 2026-02-08

## Key Principles for Gatekeeper

### 1. Session Token Security

#### Token Generation:
- Use CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)
- Minimum 128 bits of entropy (256 bits recommended)
- Never expose session tokens in URLs

```python
import secrets

# ✅ Good: Cryptographically secure
session_id = secrets.token_hex(32)  # 256 bits

# ❌ Bad: Predictable
session_id = str(uuid.uuid4())  # UUID v4 is random but only 122 bits
```

**Status in Gatekeeper:** ✅ Uses `secrets.token_hex()` for nonces

---

### 2. Token Invalidation

#### On Logout:
```python
async def logout(subject: Subject, session_store: SessionStore):
    # 1. Invalidate server-side session
    await session_store.delete(subject.session_id)
    
    # 2. Add to revocation list (for stateless tokens)
    await token_blacklist.add(subject.token_id, ttl=TOKEN_MAX_LIFETIME)
    
    # 3. Log the event
    auditor.log_logout(subject)
```

#### On Password Change:
```python
async def change_password(subject: Subject, new_password: str):
    # Update password
    await update_password_hash(subject.principal_id, new_password)
    
    # CRITICAL: Invalidate ALL sessions for this user
    await session_store.delete_all_for_principal(subject.principal_id)
    
    # Force re-authentication
    return {"message": "Password changed. Please log in again."}
```

**Status in Gatekeeper:** ❌ No session/token revocation implemented (see GAP_ANALYSIS.md #3)

---

### 3. Session Timeouts

| Timeout Type | Purpose | Recommended Value |
|--------------|---------|-------------------|
| Idle Timeout | Expire after inactivity | 15-30 minutes |
| Absolute Timeout | Max session lifetime | 4-8 hours |
| Renewal | Extend on activity | Every 5-10 minutes |

```python
@dataclass
class SessionConfig:
    idle_timeout: int = 1800  # 30 minutes
    absolute_timeout: int = 28800  # 8 hours
    renewal_interval: int = 300  # 5 minutes
```

**Status in Gatekeeper:** ❌ No session timeout management

---

### 4. Session Fixation Prevention

**Rule:** Always regenerate session ID after authentication level change.

```python
async def login(credentials: LoginCredentials) -> AuthResult:
    if verify_credentials(credentials):
        # CRITICAL: Generate NEW session, don't reuse pre-auth session
        new_session = create_session(user)
        
        # Delete any pre-existing session
        if old_session_id:
            await session_store.delete(old_session_id)
        
        return AuthResult(success=True, session_id=new_session.id)
```

---

### 5. Multi-Device Session Management

Users should be able to:
- View all active sessions
- Terminate individual sessions
- Terminate all sessions ("logout everywhere")

```python
class SessionManager:
    async def list_sessions(self, principal_id: str) -> list[SessionInfo]:
        """List all active sessions for a user."""
        return await self.store.get_sessions_for_principal(principal_id)
    
    async def terminate_session(self, principal_id: str, session_id: str) -> bool:
        """Terminate a specific session."""
        session = await self.store.get(session_id)
        if session and session.principal_id == principal_id:
            await self.store.delete(session_id)
            return True
        return False
    
    async def terminate_all_sessions(self, principal_id: str) -> int:
        """Terminate all sessions for a user."""
        return await self.store.delete_all_for_principal(principal_id)
```

**Status in Gatekeeper:** ❌ No session management UI support

---

### 6. Token Transmission

#### For APIs (Bearer tokens):
```
Authorization: Bearer <token>
```

#### Security Headers:
- Never send tokens in URL query parameters
- Use HTTPS only
- Set appropriate CORS policies

#### For Cookies:
```python
response.set_cookie(
    key="session_id",
    value=session_id,
    httponly=True,  # Prevents JavaScript access
    secure=True,    # HTTPS only
    samesite="lax", # CSRF protection
    max_age=3600,   # 1 hour
)
```

**Status in Gatekeeper:** ✅ Uses Authorization header

---

### 7. Step-Up Authentication

For sensitive operations, require re-authentication:

```python
class AuthLevel(Enum):
    BASIC = "basic"          # Standard login
    ELEVATED = "elevated"    # Recent re-auth (< 5 min)
    MFA = "mfa"              # MFA verified

def require_auth_level(level: AuthLevel):
    async def check(subject: Subject = Depends(get_current_subject)):
        if subject.auth_level < level:
            raise HTTPException(
                status_code=403,
                detail=f"This action requires {level.value} authentication",
            )
        return subject
    return check

@app.post("/api/users/{id}/delete")
async def delete_user(
    id: str,
    subject: Subject = Depends(require_auth_level(AuthLevel.ELEVATED))
):
    # User must have recently re-authenticated
    ...
```

**Status in Gatekeeper:** ❌ No step-up authentication

---

## Implementation Roadmap for Gatekeeper

### Phase 1: Token Revocation
1. Add `TokenBlacklist` class (Redis-backed)
2. Check blacklist in `AuthenticationEngine.authenticate()`
3. Add `revoke()` method to middleware

### Phase 2: Session Management
1. Add `Session` model with timeouts
2. Add `SessionStore` protocol + Redis implementation
3. Track session metadata (IP, user-agent, created_at, last_active)

### Phase 3: Multi-Session Support
1. Add `list_sessions()` API
2. Add `terminate_session()` API
3. Add "logout everywhere" functionality

---

## References

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP OAuth2 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
