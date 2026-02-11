# Aperion Gatekeeper

> **The Immune System** — Unified Authentication & Authorization for the Aperion Ecosystem

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Zero Trust](https://img.shields.io/badge/security-zero--trust-red.svg)]()

## Overview

Aperion Gatekeeper consolidates fragmented security logic (HMAC, Bearer, RBAC) into a single **Source of Truth** for identity and access control. It enforces **Constitution B (Safety & Security)** and provides a unified `enforce(subject, action, resource)` API.

### Core Principles

- **Zero Trust**: Never trust, always verify. Every request must be authenticated.
- **Default Deny**: If no explicit rule grants access, deny.
- **Fail Closed**: On any error, deny access.
- **Key Rotation**: Support multiple active keys for zero-downtime rotation.

## Installation

```bash
pip install -e .

# With development dependencies
pip install -e ".[dev]"
```

## Quick Start

### 1. Configure Key Manager

```python
from aperion_gatekeeper.core.credentials import KeyManager

# Load keys from environment
key_manager = KeyManager()
key_manager.load_hmac_from_env("APERION_HMAC_KEY")
key_manager.load_bearer_from_env("FSAL_TOKEN")
```

### 2. Authenticate Requests

```python
from aperion_gatekeeper.engines.authentication import AuthenticationEngine

engine = AuthenticationEngine(key_manager)

# Authenticate an incoming request
result = engine.authenticate(
    authorization=request.headers.get("Authorization"),
    method=request.method,
    path=request.path,
)

if result.success:
    subject = result.subject
    print(f"Authenticated: {subject.principal_id}")
else:
    print(f"Auth failed: {result.error_message}")
```

### 3. Enforce Authorization

```python
from aperion_gatekeeper.engines.policy import PolicyEngine, Permission, ResourcePolicy

policy = PolicyEngine()

# Add resource-specific policies
policy.add_policy(ResourcePolicy(
    resource_pattern="/api/admin/*",
    allowed_roles=frozenset({"admin"}),
    allowed_permissions=frozenset(Permission),
))

# Enforce access
if policy.enforce(subject, "delete", "/api/admin/users/123"):
    # Allowed
    pass
else:
    # Denied
    raise Forbidden()
```

### 4. FastAPI Integration

```python
from fastapi import Depends, FastAPI
from aperion_gatekeeper.middleware.fastapi import (
    configure_gatekeeper,
    get_current_subject,
    require_permission,
    GatekeeperConfig,
)
from aperion_gatekeeper.core.credentials import KeyManager

app = FastAPI()

# Configure at startup
@app.on_event("startup")
def setup():
    km = KeyManager()
    km.load_hmac_from_env("APERION_HMAC_KEY")
    configure_gatekeeper(GatekeeperConfig(key_manager=km))

# Protected endpoint
@app.get("/api/data")
async def get_data(subject = Depends(get_current_subject)):
    return {"user": subject.principal_id}

# Permission-protected endpoint
@app.delete("/api/data/{id}")
async def delete_data(id: str, subject = Depends(require_permission("delete"))):
    return {"deleted": id}
```

## Architecture

```
gatekeeper/
├── core/
│   ├── identity.py      # Subject, User, Agent models
│   ├── credentials.py   # KeyManager, HMAC/Token credentials
│   └── encryption.py    # Crypto utilities
├── engines/
│   ├── authentication.py # "Who are you?" (HMAC/Bearer router)
│   └── policy.py         # "Can you do this?" (RBAC engine)
├── middleware/
│   └── fastapi.py        # Drop-in FastAPI dependencies
└── audit.py              # Structured security logging
```

## Migration Plan

### Phase 1A: Core Models (COMPLETE)
- [x] Unified identity models (Subject protocol, User, Agent)
- [x] KeyManager with rotation support
- [x] Policy engine with default deny

### Phase 1B: Integration
- [ ] Migrate FSAL to use `get_current_subject`
- [ ] Migrate Cortex to use `get_current_subject`
- [ ] Replace direct HMAC validation with `AuthenticationEngine`

### Phase 2: Enhanced Security
- [ ] Add rate limiting per subject
- [ ] Add session management
- [ ] Add MFA support for User subjects
- [ ] Integrate with external identity providers

### Phase 3: Observability
- [ ] Prometheus metrics for auth success/failure rates
- [ ] OpenTelemetry tracing for auth flows
- [ ] Alert rules for security anomalies

## Source Files Migrated

| Original | Gatekeeper | Status |
|----------|------------|--------|
| `stack/aperion_zip5/hmac_auth.py` | `engines/authentication.py` | ✅ Ported |
| `stack/aperion/fsal/auth.py` | `middleware/fastapi.py` | ✅ Ported |
| `stack/aperion/security/rbac.py` | `engines/policy.py` | ✅ Ported |
| `stack/aperion/security/audit_logging.py` | `audit.py` | ✅ Ported |

## API Reference

### Subject Protocol

Every authenticated entity implements the `Subject` protocol:

```python
class Subject(Protocol):
    principal_id: str          # Unique identifier
    subject_type: SubjectType  # user, agent, service, system
    roles: frozenset[str]      # Assigned roles
    is_authenticated: bool     # Auth status
```

### AuthResult

Authentication results contain:

```python
@dataclass
class AuthResult:
    success: bool
    subject: Subject
    method: AuthMethod        # hmac, bearer, none
    error_code: AuthErrorCode | None
    error_message: str | None
```

### PolicyDecision

Policy evaluation results contain:

```python
@dataclass
class PolicyDecision:
    allowed: bool
    reason: str
    policy_matched: str | None
```

## Security Considerations

### Key Management

- Keys MUST be loaded from environment variables (Constitution B1)
- Default keys trigger warnings and should NEVER be used in production
- Use key rotation with legacy keys for zero-downtime updates

### Audit Logging

All authentication and authorization events are logged:

```python
from aperion_gatekeeper.audit import SecurityAuditor

auditor = SecurityAuditor(log_path=Path("security.jsonl"))
auditor.log_auth_success(subject, method="hmac", path="/api/data")
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Type check
mypy src/

# Lint
ruff check src/
```

## License

MIT License - See LICENSE file.
