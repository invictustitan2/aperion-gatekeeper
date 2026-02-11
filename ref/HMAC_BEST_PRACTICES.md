# HMAC Authentication Best Practices

> Source: Python documentation, OWASP, security research
> Last Updated: 2026-02-08

## Core Principles

### 1. Always Use `hmac.compare_digest()`

**NEVER use `==` or `!=` for signature comparison!**

```python
# ❌ VULNERABLE TO TIMING ATTACKS
if provided_sig == expected_sig:
    return True

# ✅ CORRECT - Constant-time comparison
import hmac
if hmac.compare_digest(provided_sig, expected_sig):
    return True
```

**Why:** Standard string comparison returns early on first mismatch, leaking timing information. Attackers can deduce correct signatures byte-by-byte by measuring response times.

**Status in Gatekeeper:** ✅ Correctly implemented in `HMACKey.verify()` and `KeyManager.verify_hmac()`

---

### 2. Key Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Key Length | 256 bits | 512 bits |
| Entropy | CSPRNG | CSPRNG |
| Storage | Environment variable | Secrets manager |
| Rotation | Quarterly | Monthly |

```python
# Generating a secure key
import secrets
key = secrets.token_hex(32)  # 256 bits
```

**Status in Gatekeeper:** ⚠️ No minimum key length enforcement (see GAP_ANALYSIS.md #4)

---

### 3. Replay Attack Prevention

#### Required Components:
1. **Timestamp** - Request freshness
2. **Nonce** - Unique per request
3. **Signature** - Covers timestamp + nonce + request

#### Timestamp Validation:
```python
SKEW_TOLERANCE = 300  # 5 minutes

def validate_timestamp(request_ts: int) -> bool:
    now = int(time.time())
    return abs(now - request_ts) <= SKEW_TOLERANCE
```

#### Nonce Tracking:
```python
# Single-instance (INSUFFICIENT for production)
used_nonces: set[str] = set()

# Distributed (REQUIRED for production)
redis.set(f"nonce:{nonce}", "1", ex=NONCE_TTL, nx=True)
```

**Status in Gatekeeper:** ⚠️ In-memory nonce tracking only (see GAP_ANALYSIS.md #1)

---

### 4. Message Format

Include all context in the signed message:

```python
# Good: Context-bound signature
message = f"{timestamp}:{nonce}:{method}:{path}"

# Better: Include body hash for POST/PUT
body_hash = hashlib.sha256(body).hexdigest()
message = f"{timestamp}:{nonce}:{method}:{path}:{body_hash}"
```

**Status in Gatekeeper:** ✅ Includes timestamp, nonce, method, path

---

### 5. Header Format

Standard: `Authorization: HMAC <timestamp>:<nonce>:<signature>`

```python
def parse_hmac_header(header: str) -> dict | None:
    if not header.startswith("HMAC "):
        return None
    
    parts = header[5:].split(":")
    if len(parts) != 3:
        return None
    
    return {
        "timestamp": int(parts[0]),
        "nonce": parts[1],
        "signature": parts[2],
    }
```

**Status in Gatekeeper:** ✅ Implemented correctly

---

### 6. Error Messages

**Security Rule:** Never reveal which part of validation failed.

```python
# ❌ BAD - Information leakage
if not valid_timestamp:
    return "Timestamp expired"
if not valid_signature:
    return "Invalid signature"

# ✅ GOOD - Generic error
return "Authentication failed"
```

**Status in Gatekeeper:** ⚠️ Currently returns specific error codes. Consider making these internal-only in production.

---

## Key Rotation Procedure

### Zero-Downtime Rotation:

1. **Generate new key**
   ```python
   new_key = secrets.token_hex(32)
   ```

2. **Add as active, demote old to legacy**
   ```python
   key_manager.add_hmac_key(new_key, status=KeyStatus.ACTIVE)
   key_manager.demote_to_legacy(old_key_id)
   ```

3. **Update clients** (give sufficient time)

4. **Revoke legacy key**
   ```python
   key_manager.revoke_key(old_key_id)
   ```

**Status in Gatekeeper:** ✅ Key rotation supported via ACTIVE/LEGACY/REVOKED states

---

## References

- [Python hmac documentation](https://docs.python.org/3/library/hmac.html)
- [HMAC RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104)
- [Timing Attacks in Python](https://sqreen.github.io/DevelopersSecurityBestPractices/timing-attack/python)
- [GitGuardian HMAC Guide](https://blog.gitguardian.com/hmac-secrets-explained-authentication/)
