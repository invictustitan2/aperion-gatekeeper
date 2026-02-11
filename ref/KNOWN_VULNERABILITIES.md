# Known Vulnerabilities in Dependencies

> Track CVEs and security issues in Gatekeeper dependencies
> Last Updated: 2026-02-08

## cryptography Library

### ⚠️ ACTION REQUIRED: Update Minimum Version

**Current pyproject.toml:**
```toml
dependencies = [
    "cryptography>=41.0.0",  # ❌ VULNERABLE
]
```

**Required Change:**
```toml
dependencies = [
    "cryptography>=42.0.4",  # ✅ Patched
]
```

---

### CVE-2024-26130 (CRITICAL)

| Field | Value |
|-------|-------|
| **CVE** | CVE-2024-26130 |
| **CVSS** | 7.5 (High) |
| **Affected** | 38.0.0 - 42.0.3 |
| **Fixed** | 42.0.4 |
| **Type** | NULL Pointer Dereference (DoS) |

**Description:**
If `pkcs12.serialize_key_and_certificates` is called with a certificate whose public key does not match the given private key, and with an encryption algorithm specifying an `hmac_hash`, a NULL pointer dereference occurs, crashing the Python process.

**Impact on Gatekeeper:**
- Gatekeeper does not currently use PKCS12 serialization
- Risk is LOW for current implementation
- Still recommended to update for defense in depth

**Mitigation:**
```bash
pip install 'cryptography>=42.0.4'
```

---

### CVE-2024-0727 (MEDIUM)

| Field | Value |
|-------|-------|
| **CVE** | CVE-2024-0727 |
| **CVSS** | 5.5 (Medium) |
| **Affected** | Multiple versions |
| **Type** | PKCS#12 File Parsing Crash |

**Description:**
A specially crafted PKCS#12 file could cause the library to crash via a NULL pointer dereference.

**Impact on Gatekeeper:**
- No PKCS#12 file loading in Gatekeeper
- Risk is NONE unless feature is added

**Recommendation:**
Never load PKCS#12 files from untrusted sources.

---

### CVE-2023-50782 (HIGH)

| Field | Value |
|-------|-------|
| **CVE** | CVE-2023-50782 |
| **CVSS** | 7.5 (High) |
| **Type** | Bleichenbacher Timing Oracle (RSA PKCS#1 v1.5) |

**Description:**
Vulnerability in the handling of incorrect padding in RSA PKCS#1 v1.5, potentially allowing a remote attacker to decrypt captured TLS messages if the application uses RSA key exchanges.

**Impact on Gatekeeper:**
- Gatekeeper uses HMAC, not RSA
- Risk is NONE for current implementation

---

## pydantic Library

### Status: ✅ No Known Vulnerabilities

Current requirement `pydantic>=2.0.0` has no known security issues.

---

## FastAPI Library

### Status: ✅ No Known Vulnerabilities

Current requirement `fastapi>=0.100.0` has no known security issues.

---

## Monitoring Tools

### pip-audit

Automatically scan for known vulnerabilities:

```bash
pip install pip-audit
pip-audit
```

### Safety

Alternative scanner:

```bash
pip install safety
safety check
```

### GitHub Dependabot

Enable in repository settings for automatic PR creation when vulnerabilities are found.

---

## Dependency Update Policy

1. **Security Updates:** Apply within 24 hours of disclosure
2. **Minor Updates:** Apply within 1 week
3. **Major Updates:** Evaluate and apply within 1 month

### Pre-Update Checklist:
- [ ] Read changelog for breaking changes
- [ ] Run full test suite
- [ ] Test in staging environment
- [ ] Monitor for 24 hours post-deployment

---

## References

- [NVD - CVE-2024-26130](https://nvd.nist.gov/vuln/detail/CVE-2024-26130)
- [PyPI Cryptography Advisories](https://advisories.gitlab.com/pkg/pypi/cryptography/)
- [Ubuntu Security Notice USN-6673-1](https://ubuntu.com/security/notices/USN-6673-1)
- [Python Advisory Database](https://github.com/pypa/advisory-database)
