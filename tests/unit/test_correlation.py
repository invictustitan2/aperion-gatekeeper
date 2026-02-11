"""Unit tests for correlation ID propagation."""

import asyncio
import threading
import pytest

from aperion_gatekeeper.core.correlation import (
    CorrelatedLogger,
    CorrelationHeaders,
    add_trace_context,
    correlation_context,
    generate_correlation_id,
    get_correlation_id,
    get_or_create_correlation_id,
    get_trace_context,
    set_correlation_id,
)


class TestCorrelationId:
    """Tests for correlation ID functions."""

    def test_generate_correlation_id_format(self) -> None:
        """Generated IDs should have correct format."""
        cid = generate_correlation_id()
        assert cid.startswith("gk-")
        assert len(cid) == 19  # "gk-" + 16 hex chars

    def test_generate_correlation_id_unique(self) -> None:
        """Generated IDs should be unique."""
        ids = {generate_correlation_id() for _ in range(1000)}
        assert len(ids) == 1000

    def test_get_correlation_id_none_by_default(self) -> None:
        """get_correlation_id returns None outside context."""
        assert get_correlation_id() is None

    def test_set_and_get_correlation_id(self) -> None:
        """set_correlation_id should set the ID."""
        prev = set_correlation_id("test-123")
        try:
            assert get_correlation_id() == "test-123"
        finally:
            set_correlation_id(prev) if prev else None

    def test_get_or_create_creates_new(self) -> None:
        """get_or_create_correlation_id creates new ID if none exists."""
        # Clear any existing
        set_correlation_id(None)

        cid = get_or_create_correlation_id()
        assert cid is not None
        assert cid.startswith("gk-")

        # Clean up
        set_correlation_id(None)


class TestCorrelationContext:
    """Tests for correlation_context context manager."""

    def test_context_sets_id(self) -> None:
        """Context manager should set correlation ID."""
        with correlation_context("req-abc") as cid:
            assert cid == "req-abc"
            assert get_correlation_id() == "req-abc"

    def test_context_generates_id_if_none(self) -> None:
        """Context manager should generate ID if none provided."""
        with correlation_context() as cid:
            assert cid is not None
            assert cid.startswith("gk-")
            assert get_correlation_id() == cid

    def test_context_restores_previous_id(self) -> None:
        """Context manager should restore previous ID on exit."""
        set_correlation_id("outer-id")

        try:
            with correlation_context("inner-id"):
                assert get_correlation_id() == "inner-id"

            assert get_correlation_id() == "outer-id"
        finally:
            set_correlation_id(None)

    def test_context_clears_on_exit(self) -> None:
        """Context should clear ID on exit if none was set before."""
        assert get_correlation_id() is None

        with correlation_context("temp-id"):
            assert get_correlation_id() == "temp-id"

        assert get_correlation_id() is None

    def test_nested_contexts(self) -> None:
        """Nested contexts should work correctly."""
        with correlation_context("outer") as outer:
            assert get_correlation_id() == "outer"

            with correlation_context("inner") as inner:
                assert get_correlation_id() == "inner"

            assert get_correlation_id() == "outer"

    def test_context_with_extra_context(self) -> None:
        """Extra context should be available via get_trace_context."""
        with correlation_context("req-123", user_id="user-456", path="/api/data"):
            context = get_trace_context()
            assert context["correlation_id"] == "req-123"
            assert context["user_id"] == "user-456"
            assert context["path"] == "/api/data"


class TestTraceContext:
    """Tests for trace context functions."""

    def test_get_trace_context_includes_correlation_id(self) -> None:
        """get_trace_context should include correlation ID."""
        with correlation_context("test-id"):
            context = get_trace_context()
            assert context["correlation_id"] == "test-id"

    def test_add_trace_context(self) -> None:
        """add_trace_context should add to current context."""
        with correlation_context("test-id"):
            add_trace_context(key1="value1", key2="value2")
            context = get_trace_context()
            assert context["key1"] == "value1"
            assert context["key2"] == "value2"


class TestCorrelationHeaders:
    """Tests for CorrelationHeaders utility."""

    def test_extract_from_headers_primary(self) -> None:
        """Should extract X-Correlation-ID header."""
        headers = {"X-Correlation-ID": "abc-123"}
        assert CorrelationHeaders.extract_from_headers(headers) == "abc-123"

    def test_extract_from_headers_request_id(self) -> None:
        """Should fall back to X-Request-ID header."""
        headers = {"X-Request-ID": "req-456"}
        assert CorrelationHeaders.extract_from_headers(headers) == "req-456"

    def test_extract_from_headers_trace_id(self) -> None:
        """Should fall back to X-Trace-ID header."""
        headers = {"X-Trace-ID": "trace-789"}
        assert CorrelationHeaders.extract_from_headers(headers) == "trace-789"

    def test_extract_from_headers_priority(self) -> None:
        """X-Correlation-ID should take priority."""
        headers = {
            "X-Correlation-ID": "primary",
            "X-Request-ID": "secondary",
            "X-Trace-ID": "tertiary",
        }
        assert CorrelationHeaders.extract_from_headers(headers) == "primary"

    def test_extract_from_headers_case_insensitive(self) -> None:
        """Header matching should be case-insensitive."""
        headers = {"x-correlation-id": "lowercase"}
        assert CorrelationHeaders.extract_from_headers(headers) == "lowercase"

    def test_extract_from_headers_none(self) -> None:
        """Should return None if no headers present."""
        headers = {"Content-Type": "application/json"}
        assert CorrelationHeaders.extract_from_headers(headers) is None

    def test_to_headers_basic(self) -> None:
        """to_headers should create headers dict."""
        headers = CorrelationHeaders.to_headers("test-123")
        assert headers == {"X-Correlation-ID": "test-123"}

    def test_to_headers_with_alternatives(self) -> None:
        """to_headers should include alternatives when requested."""
        headers = CorrelationHeaders.to_headers("test-123", include_alternatives=True)
        assert headers["X-Correlation-ID"] == "test-123"
        assert headers["X-Request-ID"] == "test-123"
        assert headers["X-Trace-ID"] == "test-123"


class TestThreadSafety:
    """Tests for thread safety of correlation context."""

    def test_thread_isolation(self) -> None:
        """Correlation ID should be isolated per thread."""
        results = {}
        errors = []

        def thread_work(thread_id: int):
            try:
                with correlation_context(f"thread-{thread_id}"):
                    # Do some work
                    for _ in range(100):
                        cid = get_correlation_id()
                        if cid != f"thread-{thread_id}":
                            errors.append(f"Thread {thread_id} got wrong ID: {cid}")
                            return
                    results[thread_id] = get_correlation_id()
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=thread_work, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(results) == 10
        for i in range(10):
            assert results[i] == f"thread-{i}"


class TestAsyncSafety:
    """Tests for async safety of correlation context."""

    @pytest.mark.asyncio
    async def test_async_isolation(self) -> None:
        """Correlation ID should be isolated per async task."""
        results = {}

        async def async_work(task_id: int):
            with correlation_context(f"task-{task_id}"):
                await asyncio.sleep(0.01)  # Yield to event loop
                results[task_id] = get_correlation_id()

        await asyncio.gather(*[async_work(i) for i in range(10)])

        assert len(results) == 10
        for i in range(10):
            assert results[i] == f"task-{i}"


class TestCorrelatedLogger:
    """Tests for CorrelatedLogger wrapper."""

    def test_logger_adds_correlation_id(self, caplog: pytest.LogCaptureFixture) -> None:
        """Logger should add correlation ID to log records."""
        import logging

        logger = CorrelatedLogger(logging.getLogger("test"))

        with correlation_context("log-test-123"):
            with caplog.at_level(logging.INFO):
                logger.info("Test message")

        assert len(caplog.records) == 1
        assert caplog.records[0].correlation_id == "log-test-123"

    def test_logger_methods(self) -> None:
        """All logger methods should be available."""
        import logging

        logger = CorrelatedLogger(logging.getLogger("test"))

        # Just verify methods exist and are callable
        assert callable(logger.debug)
        assert callable(logger.info)
        assert callable(logger.warning)
        assert callable(logger.error)
        assert callable(logger.critical)
        assert callable(logger.exception)
