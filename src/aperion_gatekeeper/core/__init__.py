"""Core identity and credential models."""

from aperion_gatekeeper.core.correlation import (
    CorrelatedLogger,
    CorrelationHeaders,
    correlation_context,
    generate_correlation_id,
    get_correlation_id,
    get_or_create_correlation_id,
    get_trace_context,
    set_correlation_id,
)
from aperion_gatekeeper.core.credentials import Credential, HMACKey, KeyManager, TokenCredential
from aperion_gatekeeper.core.identity import Agent, Subject, SubjectType, User

__all__ = [
    "Subject",
    "SubjectType",
    "User",
    "Agent",
    "Credential",
    "HMACKey",
    "TokenCredential",
    "KeyManager",
    # Correlation
    "correlation_context",
    "get_correlation_id",
    "set_correlation_id",
    "get_or_create_correlation_id",
    "generate_correlation_id",
    "get_trace_context",
    "CorrelationHeaders",
    "CorrelatedLogger",
]
