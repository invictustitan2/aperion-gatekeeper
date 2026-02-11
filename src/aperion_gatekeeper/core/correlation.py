"""
Correlation ID Context for Request Tracing.

Provides thread-local and async-safe correlation ID propagation
for end-to-end request tracing across service boundaries.

Usage:
    # In middleware (start of request)
    with correlation_context(request_id="abc-123"):
        # All code in this block will have access to the correlation ID
        process_request()

    # Anywhere in the request lifecycle
    current_id = get_correlation_id()  # Returns "abc-123"

    # In logs
    logger.info("Processing", extra={"correlation_id": get_correlation_id()})
"""

from __future__ import annotations

import contextvars
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Generator

# Context variable for async-safe correlation ID storage
_correlation_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "correlation_id", default=None
)

# Additional context for rich tracing
_trace_context: contextvars.ContextVar[dict[str, Any]] = contextvars.ContextVar(
    "trace_context", default={}
)


def get_correlation_id() -> str | None:
    """
    Get the current correlation ID.

    Returns:
        Current correlation ID or None if not in a correlation context
    """
    return _correlation_id.get()


def get_or_create_correlation_id() -> str:
    """
    Get existing correlation ID or create a new one.

    Returns:
        Current or new correlation ID
    """
    current = _correlation_id.get()
    if current is None:
        current = generate_correlation_id()
        _correlation_id.set(current)
    return current


def set_correlation_id(correlation_id: str) -> str | None:
    """
    Set the correlation ID for the current context.

    Args:
        correlation_id: ID to set

    Returns:
        Previous correlation ID (for restoration)
    """
    previous = _correlation_id.get()
    _correlation_id.set(correlation_id)
    return previous


def generate_correlation_id() -> str:
    """
    Generate a new correlation ID.

    Format: gk-{uuid4} (gk = gatekeeper)

    Returns:
        New unique correlation ID
    """
    return f"gk-{uuid.uuid4().hex[:16]}"


@contextmanager
def correlation_context(
    correlation_id: str | None = None,
    **extra_context: Any,
) -> Generator[str, None, None]:
    """
    Context manager for correlation ID scope.

    Automatically sets and clears the correlation ID for the duration
    of the context. Safe for both sync and async code.

    Args:
        correlation_id: ID to use (generates new one if None)
        **extra_context: Additional context to store (e.g., user_id, request_path)

    Yields:
        The active correlation ID

    Example:
        with correlation_context() as cid:
            # cid is available here
            logger.info("Request started", extra={"correlation_id": cid})
            process_request()
    """
    # Generate ID if not provided
    cid = correlation_id or generate_correlation_id()

    # Save previous state
    prev_id = _correlation_id.get()
    prev_context = _trace_context.get()

    # Set new state
    _correlation_id.set(cid)
    if extra_context:
        new_context = {**prev_context, **extra_context, "correlation_id": cid}
        _trace_context.set(new_context)

    try:
        yield cid
    finally:
        # Restore previous state
        _correlation_id.set(prev_id)
        _trace_context.set(prev_context)


def get_trace_context() -> dict[str, Any]:
    """
    Get the full trace context.

    Returns:
        Dictionary with correlation_id and any extra context
    """
    context = dict(_trace_context.get())
    context["correlation_id"] = _correlation_id.get()
    return context


def add_trace_context(**kwargs: Any) -> None:
    """
    Add additional context to the current trace.

    Args:
        **kwargs: Key-value pairs to add to trace context
    """
    current = dict(_trace_context.get())
    current.update(kwargs)
    _trace_context.set(current)


@dataclass
class CorrelationHeaders:
    """
    Standard headers for correlation ID propagation.

    Use these constants for consistent header names across services.
    """

    # Primary correlation ID header
    CORRELATION_ID: str = "X-Correlation-ID"

    # Alternative names (for compatibility)
    REQUEST_ID: str = "X-Request-ID"
    TRACE_ID: str = "X-Trace-ID"

    # Parent span for distributed tracing
    PARENT_ID: str = "X-Parent-ID"

    @classmethod
    def extract_from_headers(
        cls,
        headers: dict[str, str],
    ) -> str | None:
        """
        Extract correlation ID from request headers.

        Checks multiple header names for compatibility.

        Args:
            headers: Request headers (case-insensitive keys)

        Returns:
            Correlation ID if found, None otherwise
        """
        # Normalize header keys to lowercase
        normalized = {k.lower(): v for k, v in headers.items()}

        # Check headers in priority order
        for header in [
            cls.CORRELATION_ID.lower(),
            cls.REQUEST_ID.lower(),
            cls.TRACE_ID.lower(),
        ]:
            if header in normalized:
                return normalized[header]

        return None

    @classmethod
    def to_headers(
        cls,
        correlation_id: str,
        *,
        include_alternatives: bool = False,
    ) -> dict[str, str]:
        """
        Create headers dict with correlation ID.

        Args:
            correlation_id: ID to include
            include_alternatives: Also include X-Request-ID, X-Trace-ID

        Returns:
            Headers dictionary
        """
        headers = {cls.CORRELATION_ID: correlation_id}

        if include_alternatives:
            headers[cls.REQUEST_ID] = correlation_id
            headers[cls.TRACE_ID] = correlation_id

        return headers


class CorrelatedLogger:
    """
    Logger wrapper that automatically includes correlation ID.

    Wraps a standard Python logger to add correlation context to all log messages.

    Usage:
        import logging
        logger = CorrelatedLogger(logging.getLogger("myapp"))

        with correlation_context("req-123"):
            logger.info("Processing request")
            # Log output includes: {"correlation_id": "req-123", ...}
    """

    def __init__(self, logger: Any) -> None:
        """
        Initialize correlated logger.

        Args:
            logger: Python logger instance to wrap
        """
        self._logger = logger

    def _add_correlation(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        """Add correlation ID to log extra dict."""
        extra = kwargs.get("extra", {})
        extra["correlation_id"] = get_correlation_id()
        extra.update(get_trace_context())
        kwargs["extra"] = extra
        return kwargs

    def debug(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log debug message with correlation ID."""
        self._logger.debug(msg, *args, **self._add_correlation(kwargs))

    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log info message with correlation ID."""
        self._logger.info(msg, *args, **self._add_correlation(kwargs))

    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log warning message with correlation ID."""
        self._logger.warning(msg, *args, **self._add_correlation(kwargs))

    def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log error message with correlation ID."""
        self._logger.error(msg, *args, **self._add_correlation(kwargs))

    def critical(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log critical message with correlation ID."""
        self._logger.critical(msg, *args, **self._add_correlation(kwargs))

    def exception(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log exception with correlation ID."""
        self._logger.exception(msg, *args, **self._add_correlation(kwargs))
