"""Protocol logging for authentication flows.

Provides detailed HTTP-level logging for debugging authentication issues,
with configurable log levels and sensitive data protection.

Log levels:
- ERROR: Only log errors
- INFO: Log flow milestones (requests initiated, responses received)
- DEBUG: Log HTTP details (headers, status codes, timing)
- TRACE: Log full request/response bodies including sensitive data (requires explicit enable)
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum
from typing import Any

import httpx

# Custom log level for TRACE (below DEBUG)
TRACE = 5
logging.addLevelName(TRACE, "TRACE")

# Module logger
logger = logging.getLogger("authtest.protocol")


class LogLevel(IntEnum):
    """Protocol logging levels."""

    ERROR = logging.ERROR  # 40
    INFO = logging.INFO  # 20
    DEBUG = logging.DEBUG  # 10
    TRACE = TRACE  # 5


# Patterns for sensitive data redaction
SENSITIVE_PATTERNS = [
    # OAuth/OIDC
    (re.compile(r"(client_secret=)[^&\s]+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(code=)[^&\s]+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(access_token=)[^&\s]+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(refresh_token=)[^&\s]+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(id_token=)[^&\s]+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(code_verifier=)[^&\s]+", re.IGNORECASE), r"\1[REDACTED]"),
    # HTTP headers (with or without "Authorization:" prefix for header dict values)
    (re.compile(r"(Authorization:\s*Bearer\s+)[^\s]+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(Authorization:\s*Basic\s+)[^\s]+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"^(Bearer\s+)[^\s]+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"^(Basic\s+)[^\s]+", re.IGNORECASE), r"\1[REDACTED]"),
    # Cookies
    (re.compile(r"(Cookie:\s*)[^\r\n]+", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(Set-Cookie:\s*)[^\r\n]+", re.IGNORECASE), r"\1[REDACTED]"),
    # JSON fields
    (re.compile(r'"(client_secret)"\s*:\s*"[^"]+"', re.IGNORECASE), r'"\1": "[REDACTED]"'),
    (re.compile(r'"(access_token)"\s*:\s*"[^"]+"', re.IGNORECASE), r'"\1": "[REDACTED]"'),
    (re.compile(r'"(refresh_token)"\s*:\s*"[^"]+"', re.IGNORECASE), r'"\1": "[REDACTED]"'),
    (re.compile(r'"(id_token)"\s*:\s*"[^"]+"', re.IGNORECASE), r'"\1": "[REDACTED]"'),
    (re.compile(r'"(password)"\s*:\s*"[^"]+"', re.IGNORECASE), r'"\1": "[REDACTED]"'),
]


def redact_sensitive(text: str) -> str:
    """Redact sensitive information from text.

    Args:
        text: Text that may contain sensitive data.

    Returns:
        Text with sensitive data redacted.
    """
    result = text
    for pattern, replacement in SENSITIVE_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


@dataclass
class HTTPExchange:
    """Represents a single HTTP request/response exchange."""

    id: str
    timestamp: datetime
    method: str
    url: str
    request_headers: dict[str, str]
    request_body: str | None = None
    response_status: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str | None = None
    duration_ms: float | None = None
    error: str | None = None
    redirects: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self, include_sensitive: bool = False) -> dict[str, Any]:
        """Convert to dictionary for serialization.

        Args:
            include_sensitive: If True, include raw sensitive data.
                               If False, redact sensitive information.

        Returns:
            Dictionary representation of the exchange.
        """
        def process(value: str | None) -> str | None:
            if value is None:
                return None
            return value if include_sensitive else redact_sensitive(value)

        def process_headers(headers: dict[str, str]) -> dict[str, str]:
            if include_sensitive:
                return dict(headers)
            return {k: redact_sensitive(v) for k, v in headers.items()}

        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "method": self.method,
            "url": self.url if include_sensitive else redact_sensitive(self.url),
            "request_headers": process_headers(self.request_headers),
            "request_body": process(self.request_body),
            "response_status": self.response_status,
            "response_headers": process_headers(self.response_headers),
            "response_body": process(self.response_body),
            "duration_ms": self.duration_ms,
            "error": self.error,
            "redirects": [
                {
                    "url": r["url"] if include_sensitive else redact_sensitive(r["url"]),
                    "status": r.get("status"),
                }
                for r in self.redirects
            ],
        }

    def format_log(self, level: LogLevel, include_sensitive: bool = False) -> str:
        """Format the exchange for logging.

        Args:
            level: Log level determines how much detail to include.
            include_sensitive: If True, include raw sensitive data.

        Returns:
            Formatted log string.
        """
        lines = []
        url = self.url if include_sensitive else redact_sensitive(self.url)

        if level >= LogLevel.INFO:
            # Basic request/response info
            status = self.response_status or "ERROR"
            lines.append(f"HTTP {self.method} {url} -> {status}")

            if self.duration_ms is not None:
                lines.append(f"  Duration: {self.duration_ms:.1f}ms")

            if self.error:
                lines.append(f"  Error: {self.error}")

        if level <= LogLevel.DEBUG:
            # Include headers
            lines.append("  Request Headers:")
            for name, value in self.request_headers.items():
                display_value = value if include_sensitive else redact_sensitive(value)
                lines.append(f"    {name}: {display_value}")

            if self.response_headers:
                lines.append("  Response Headers:")
                for name, value in self.response_headers.items():
                    display_value = value if include_sensitive else redact_sensitive(value)
                    lines.append(f"    {name}: {display_value}")

            # Include redirects
            if self.redirects:
                lines.append("  Redirects:")
                for redirect in self.redirects:
                    rurl = redirect["url"] if include_sensitive else redact_sensitive(redirect["url"])
                    lines.append(f"    -> {redirect.get('status', '???')} {rurl}")

        if level <= LogLevel.TRACE:
            # Include bodies (TRACE level)
            if self.request_body:
                body = self.request_body if include_sensitive else redact_sensitive(self.request_body)
                lines.append("  Request Body:")
                lines.append(f"    {body[:2000]}{'...' if len(body) > 2000 else ''}")

            if self.response_body:
                body = self.response_body if include_sensitive else redact_sensitive(self.response_body)
                lines.append("  Response Body:")
                lines.append(f"    {body[:2000]}{'...' if len(body) > 2000 else ''}")

        return "\n".join(lines)


@dataclass
class ProtocolLog:
    """Collects protocol exchanges for a flow or session."""

    flow_id: str
    flow_type: str
    exchanges: list[HTTPExchange] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None

    def add_exchange(self, exchange: HTTPExchange) -> None:
        """Add an HTTP exchange to the log."""
        self.exchanges.append(exchange)

    def complete(self) -> None:
        """Mark the log as complete."""
        self.completed_at = datetime.now(UTC)

    def to_dict(self, include_sensitive: bool = False) -> dict[str, Any]:
        """Convert to dictionary for serialization.

        Args:
            include_sensitive: If True, include raw sensitive data.

        Returns:
            Dictionary representation of the protocol log.
        """
        return {
            "flow_id": self.flow_id,
            "flow_type": self.flow_type,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "exchanges": [e.to_dict(include_sensitive) for e in self.exchanges],
            "exchange_count": len(self.exchanges),
        }


class ProtocolLogger:
    """Configurable protocol logger for authentication flows.

    Manages log level settings and provides HTTP transport hooks
    for capturing request/response data.
    """

    def __init__(
        self,
        level: LogLevel = LogLevel.INFO,
        trace_enabled: bool = False,
    ) -> None:
        """Initialize the protocol logger.

        Args:
            level: Minimum log level.
            trace_enabled: Whether TRACE level is enabled (for sensitive data).
        """
        self._level = level
        self._trace_enabled = trace_enabled
        self._current_log: ProtocolLog | None = None
        self._exchange_counter = 0

    @property
    def level(self) -> LogLevel:
        """Get current log level."""
        return self._level

    @level.setter
    def level(self, value: LogLevel) -> None:
        """Set log level."""
        self._level = value

    @property
    def trace_enabled(self) -> bool:
        """Whether TRACE level is enabled."""
        return self._trace_enabled

    @trace_enabled.setter
    def trace_enabled(self, value: bool) -> None:
        """Enable or disable TRACE level."""
        self._trace_enabled = value

    @property
    def effective_level(self) -> LogLevel:
        """Get effective log level (TRACE only if explicitly enabled)."""
        if self._level == LogLevel.TRACE and not self._trace_enabled:
            return LogLevel.DEBUG
        return self._level

    def start_flow(self, flow_id: str, flow_type: str) -> ProtocolLog:
        """Start logging a new flow.

        Args:
            flow_id: Unique identifier for the flow.
            flow_type: Type of flow (e.g., "oidc_authorization_code", "saml_sso").

        Returns:
            ProtocolLog for the flow.
        """
        self._current_log = ProtocolLog(flow_id=flow_id, flow_type=flow_type)
        logger.info(f"Started protocol logging for {flow_type} flow: {flow_id}")
        return self._current_log

    def end_flow(self) -> ProtocolLog | None:
        """End the current flow and return the log.

        Returns:
            The completed ProtocolLog, or None if no flow was active.
        """
        if self._current_log:
            self._current_log.complete()
            log = self._current_log
            logger.info(
                f"Completed protocol logging for {log.flow_type} flow: {log.flow_id} "
                f"({len(log.exchanges)} exchanges)"
            )
            self._current_log = None
            return log
        return None

    def log_exchange(self, exchange: HTTPExchange) -> None:
        """Log an HTTP exchange.

        Args:
            exchange: The HTTP exchange to log.
        """
        # Add to current flow log
        if self._current_log:
            self._current_log.add_exchange(exchange)

        # Log to Python logger at appropriate level
        effective = self.effective_level
        include_sensitive = self._trace_enabled and self._level <= LogLevel.TRACE

        if effective <= LogLevel.DEBUG:
            log_text = exchange.format_log(effective, include_sensitive)
            logger.debug(log_text)
        elif effective <= LogLevel.INFO:
            log_text = exchange.format_log(effective, include_sensitive)
            logger.info(log_text)

        if exchange.error:
            logger.error(f"HTTP error: {exchange.method} {exchange.url}: {exchange.error}")

    def create_transport(self) -> LoggingTransport:
        """Create an httpx transport that logs requests/responses.

        Returns:
            LoggingTransport configured with this logger.
        """
        return LoggingTransport(self)


class LoggingTransport(httpx.BaseTransport):
    """HTTPX transport that logs all HTTP exchanges."""

    def __init__(self, protocol_logger: ProtocolLogger) -> None:
        """Initialize the logging transport.

        Args:
            protocol_logger: ProtocolLogger to use for logging.
        """
        self._logger = protocol_logger
        self._transport = httpx.HTTPTransport()
        self._exchange_counter = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Handle an HTTP request with logging.

        Args:
            request: The outgoing request.

        Returns:
            The response from the server.
        """
        self._exchange_counter += 1
        exchange_id = f"http_{self._exchange_counter:04d}"
        start_time = time.perf_counter()

        # Capture request details
        request_headers = dict(request.headers)
        request_body = None
        if request.content:
            try:
                request_body = request.content.decode("utf-8")
            except (UnicodeDecodeError, AttributeError):
                request_body = "<binary content>"

        exchange = HTTPExchange(
            id=exchange_id,
            timestamp=datetime.now(UTC),
            method=request.method,
            url=str(request.url),
            request_headers=request_headers,
            request_body=request_body,
        )

        try:
            response = self._transport.handle_request(request)
            end_time = time.perf_counter()

            # Capture response details
            exchange.response_status = response.status_code
            exchange.response_headers = dict(response.headers)
            exchange.duration_ms = (end_time - start_time) * 1000

            # Capture response body (for logging only, don't consume the stream)
            if response.is_stream_consumed:
                # Response was already read
                pass
            else:
                # Read response for logging
                try:
                    response.read()
                    exchange.response_body = response.text
                except Exception:
                    exchange.response_body = "<error reading body>"

            self._logger.log_exchange(exchange)
            return response

        except Exception as e:
            end_time = time.perf_counter()
            exchange.duration_ms = (end_time - start_time) * 1000
            exchange.error = str(e)
            self._logger.log_exchange(exchange)
            raise

    def close(self) -> None:
        """Close the underlying transport."""
        self._transport.close()


class LoggingClient(httpx.Client):
    """HTTPX client with protocol logging support."""

    def __init__(
        self,
        protocol_logger: ProtocolLogger | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the logging client.

        Args:
            protocol_logger: ProtocolLogger to use. Creates default if not provided.
            **kwargs: Additional arguments passed to httpx.Client.
        """
        self._protocol_logger = protocol_logger or ProtocolLogger()

        # Don't use custom transport if follow_redirects is enabled
        # as we want to track redirects manually
        if "follow_redirects" not in kwargs:
            kwargs["follow_redirects"] = False

        super().__init__(**kwargs)

    @property
    def protocol_logger(self) -> ProtocolLogger:
        """Get the protocol logger."""
        return self._protocol_logger

    def _log_request_response(
        self,
        request: httpx.Request,
        response: httpx.Response,
        start_time: float,
        redirects: list[dict[str, Any]],
    ) -> None:
        """Log a request/response pair."""
        end_time = time.perf_counter()

        # Capture request details
        request_headers = dict(request.headers)
        request_body = None
        if request.content:
            try:
                request_body = request.content.decode("utf-8")
            except (UnicodeDecodeError, AttributeError):
                request_body = "<binary content>"

        # Capture response details
        response_body = None
        try:
            response_body = response.text
        except Exception:
            response_body = "<error reading body>"

        exchange = HTTPExchange(
            id=f"http_{id(request):08x}",
            timestamp=datetime.now(UTC),
            method=request.method,
            url=str(request.url),
            request_headers=request_headers,
            request_body=request_body,
            response_status=response.status_code,
            response_headers=dict(response.headers),
            response_body=response_body,
            duration_ms=(end_time - start_time) * 1000,
            redirects=redirects,
        )

        self._protocol_logger.log_exchange(exchange)

    def request(self, method: str, url: str | httpx.URL, **kwargs: Any) -> httpx.Response:
        """Make an HTTP request with logging.

        Handles redirect following manually to capture redirect chain.
        """
        start_time = time.perf_counter()
        redirects: list[dict[str, Any]] = []
        max_redirects = 10

        # Build the initial request
        request = self.build_request(method, url, **kwargs)

        # Make the request
        response = super().send(request)

        # Follow redirects manually to track them
        while response.is_redirect and len(redirects) < max_redirects:
            redirect_url = response.headers.get("location", "")
            redirects.append({
                "url": redirect_url,
                "status": response.status_code,
            })

            # Follow the redirect
            if redirect_url:
                # Handle relative URLs
                if redirect_url.startswith("/"):
                    redirect_url = f"{request.url.scheme}://{request.url.host}{redirect_url}"

                request = self.build_request("GET", redirect_url)
                response = super().send(request)

        # Log the final exchange with all redirects
        self._log_request_response(request, response, start_time, redirects)

        return response


# Global protocol logger instance
_global_logger: ProtocolLogger | None = None


def get_protocol_logger() -> ProtocolLogger:
    """Get the global protocol logger instance.

    Returns:
        The global ProtocolLogger.
    """
    global _global_logger
    if _global_logger is None:
        _global_logger = ProtocolLogger()
    return _global_logger


def set_protocol_logger(logger_instance: ProtocolLogger) -> None:
    """Set the global protocol logger instance.

    Args:
        logger_instance: ProtocolLogger to use globally.
    """
    global _global_logger
    _global_logger = logger_instance


def configure_logging(
    level: LogLevel | str = LogLevel.INFO,
    trace_enabled: bool = False,
    log_file: str | None = None,
) -> ProtocolLogger:
    """Configure protocol logging.

    Args:
        level: Log level (ERROR, INFO, DEBUG, TRACE) or string name.
        trace_enabled: Whether to enable TRACE level (includes sensitive data).
        log_file: Optional file path to write logs to.

    Returns:
        Configured ProtocolLogger.
    """
    # Parse level if string
    if isinstance(level, str):
        level_map = {
            "ERROR": LogLevel.ERROR,
            "INFO": LogLevel.INFO,
            "DEBUG": LogLevel.DEBUG,
            "TRACE": LogLevel.TRACE,
        }
        level = level_map.get(level.upper(), LogLevel.INFO)

    # Configure Python logger
    logger.setLevel(level)

    # Remove existing handlers
    logger.handlers.clear()

    # Add console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Add file handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    # Create and set global protocol logger
    protocol_logger = ProtocolLogger(level=level, trace_enabled=trace_enabled)
    set_protocol_logger(protocol_logger)

    # Log configuration (but warn about TRACE)
    if trace_enabled:
        logger.warning(
            "TRACE logging enabled - sensitive data (tokens, secrets) will be logged!"
        )

    return protocol_logger
