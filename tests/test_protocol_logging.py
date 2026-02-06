"""Tests for protocol logging module."""

import pytest
from datetime import UTC, datetime

from authtest.core.logging import (
    HTTPExchange,
    LogLevel,
    ProtocolLog,
    ProtocolLogger,
    configure_logging,
    get_protocol_logger,
    redact_sensitive,
    set_protocol_logger,
)


class TestRedactSensitive:
    """Tests for sensitive data redaction."""

    def test_redact_client_secret(self):
        """Test redacting client_secret in query string."""
        text = "client_secret=super-secret-value&client_id=my-app"
        result = redact_sensitive(text)
        assert "super-secret-value" not in result
        assert "[REDACTED]" in result
        assert "my-app" in result  # client_id should not be redacted

    def test_redact_access_token(self):
        """Test redacting access_token."""
        text = "access_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature"
        result = redact_sensitive(text)
        assert "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9" not in result
        assert "[REDACTED]" in result

    def test_redact_authorization_header(self):
        """Test redacting Authorization header."""
        text = "Authorization: Bearer my-secret-token"
        result = redact_sensitive(text)
        assert "my-secret-token" not in result
        assert "[REDACTED]" in result

    def test_redact_cookie_header(self):
        """Test redacting Cookie header."""
        text = "Cookie: session=abc123; user=john"
        result = redact_sensitive(text)
        assert "session=abc123" not in result
        assert "[REDACTED]" in result

    def test_redact_json_fields(self):
        """Test redacting sensitive JSON fields."""
        text = '{"client_secret": "my-secret", "grant_type": "authorization_code"}'
        result = redact_sensitive(text)
        assert "my-secret" not in result
        assert "[REDACTED]" in result
        assert "authorization_code" in result

    def test_no_redact_normal_text(self):
        """Test that normal text is not modified."""
        text = "This is a normal log message without sensitive data."
        result = redact_sensitive(text)
        assert result == text


class TestHTTPExchange:
    """Tests for HTTPExchange dataclass."""

    def test_to_dict_without_sensitive(self):
        """Test serialization with sensitive data redacted."""
        exchange = HTTPExchange(
            id="test_001",
            timestamp=datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            method="POST",
            url="https://idp.example.com/token?client_secret=secret",
            request_headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": "Basic base64credentials",
            },
            request_body="grant_type=authorization_code&code=auth-code-123",
            response_status=200,
            response_headers={
                "Content-Type": "application/json",
            },
            response_body='{"access_token": "jwt-token-here", "token_type": "Bearer"}',
            duration_ms=150.5,
        )

        result = exchange.to_dict(include_sensitive=False)

        assert result["id"] == "test_001"
        assert result["method"] == "POST"
        assert "[REDACTED]" in result["url"]
        assert "[REDACTED]" in result["request_headers"]["Authorization"]
        assert "[REDACTED]" in result["request_body"]
        assert "[REDACTED]" in result["response_body"]

    def test_to_dict_with_sensitive(self):
        """Test serialization with sensitive data included."""
        exchange = HTTPExchange(
            id="test_001",
            timestamp=datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            method="POST",
            url="https://idp.example.com/token?client_secret=secret",
            request_headers={"Authorization": "Basic base64credentials"},
            request_body="grant_type=authorization_code&code=auth-code-123",
        )

        result = exchange.to_dict(include_sensitive=True)

        assert "secret" in result["url"]
        assert "base64credentials" in result["request_headers"]["Authorization"]
        assert "auth-code-123" in result["request_body"]

    def test_format_log_info_level(self):
        """Test log formatting at INFO level."""
        exchange = HTTPExchange(
            id="test_001",
            timestamp=datetime.now(UTC),
            method="GET",
            url="https://idp.example.com/.well-known/openid-configuration",
            request_headers={},
            response_status=200,
            duration_ms=50.0,
        )

        log = exchange.format_log(LogLevel.INFO)
        assert "GET" in log
        assert "200" in log
        assert "50.0ms" in log
        # INFO level should not include headers
        assert "Request Headers" not in log

    def test_format_log_debug_level(self):
        """Test log formatting at DEBUG level."""
        exchange = HTTPExchange(
            id="test_001",
            timestamp=datetime.now(UTC),
            method="GET",
            url="https://idp.example.com/userinfo",
            request_headers={"Authorization": "Bearer token"},
            response_status=200,
            response_headers={"Content-Type": "application/json"},
        )

        log = exchange.format_log(LogLevel.DEBUG)
        assert "Request Headers" in log
        assert "Response Headers" in log
        assert "[REDACTED]" in log  # Authorization should be redacted


class TestProtocolLog:
    """Tests for ProtocolLog dataclass."""

    def test_add_exchange(self):
        """Test adding exchanges to a protocol log."""
        log = ProtocolLog(flow_id="test_flow", flow_type="oidc_authorization_code")

        exchange1 = HTTPExchange(
            id="ex_001",
            timestamp=datetime.now(UTC),
            method="GET",
            url="https://example.com/auth",
            request_headers={},
        )
        exchange2 = HTTPExchange(
            id="ex_002",
            timestamp=datetime.now(UTC),
            method="POST",
            url="https://example.com/token",
            request_headers={},
        )

        log.add_exchange(exchange1)
        log.add_exchange(exchange2)

        assert len(log.exchanges) == 2

    def test_complete(self):
        """Test marking a log as complete."""
        log = ProtocolLog(flow_id="test_flow", flow_type="oidc_authorization_code")
        assert log.completed_at is None

        log.complete()
        assert log.completed_at is not None

    def test_to_dict(self):
        """Test serializing a protocol log."""
        log = ProtocolLog(flow_id="test_flow", flow_type="oidc_authorization_code")
        log.add_exchange(
            HTTPExchange(
                id="ex_001",
                timestamp=datetime.now(UTC),
                method="GET",
                url="https://example.com/auth",
                request_headers={},
            )
        )
        log.complete()

        result = log.to_dict()
        assert result["flow_id"] == "test_flow"
        assert result["flow_type"] == "oidc_authorization_code"
        assert result["exchange_count"] == 1
        assert result["completed_at"] is not None


class TestProtocolLogger:
    """Tests for ProtocolLogger class."""

    def test_default_log_level(self):
        """Test default log level is INFO."""
        logger = ProtocolLogger()
        assert logger.level == LogLevel.INFO

    def test_set_log_level(self):
        """Test setting log level."""
        logger = ProtocolLogger(level=LogLevel.DEBUG)
        assert logger.level == LogLevel.DEBUG

        logger.level = LogLevel.ERROR
        assert logger.level == LogLevel.ERROR

    def test_trace_requires_explicit_enable(self):
        """Test that TRACE level requires explicit enable."""
        logger = ProtocolLogger(level=LogLevel.TRACE, trace_enabled=False)
        assert logger.effective_level == LogLevel.DEBUG

        logger.trace_enabled = True
        assert logger.effective_level == LogLevel.TRACE

    def test_start_and_end_flow(self):
        """Test starting and ending a flow."""
        logger = ProtocolLogger()

        log = logger.start_flow("test_123", "oidc_authorization_code")
        assert log.flow_id == "test_123"
        assert log.flow_type == "oidc_authorization_code"

        result = logger.end_flow()
        assert result is log
        assert result.completed_at is not None

    def test_log_exchange(self):
        """Test logging an exchange."""
        logger = ProtocolLogger()
        log = logger.start_flow("test_123", "oidc")

        exchange = HTTPExchange(
            id="ex_001",
            timestamp=datetime.now(UTC),
            method="GET",
            url="https://example.com/auth",
            request_headers={},
            response_status=200,
        )

        logger.log_exchange(exchange)
        assert len(log.exchanges) == 1


class TestConfigureLogging:
    """Tests for configure_logging function."""

    def test_configure_with_defaults(self):
        """Test configuring with default settings."""
        logger = configure_logging()
        assert logger.level == LogLevel.INFO
        assert not logger.trace_enabled

    def test_configure_with_string_level(self):
        """Test configuring with string log level."""
        logger = configure_logging(level="DEBUG")
        assert logger.level == LogLevel.DEBUG

    def test_configure_trace_warning(self):
        """Test that enabling TRACE logs a warning."""
        logger = configure_logging(level=LogLevel.TRACE, trace_enabled=True)
        assert logger.trace_enabled


class TestGlobalLogger:
    """Tests for global logger management."""

    def test_get_protocol_logger(self):
        """Test getting the global protocol logger."""
        logger1 = get_protocol_logger()
        logger2 = get_protocol_logger()
        assert logger1 is logger2

    def test_set_protocol_logger(self):
        """Test setting the global protocol logger."""
        custom_logger = ProtocolLogger(level=LogLevel.DEBUG)
        set_protocol_logger(custom_logger)

        retrieved = get_protocol_logger()
        assert retrieved is custom_logger
        assert retrieved.level == LogLevel.DEBUG
