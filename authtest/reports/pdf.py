"""PDF report generator using WeasyPrint.

Generates professional PDF reports from test results with:
- Company/project details header
- Test execution summary
- Detailed token and validation results
- Optional sensitive data redaction
"""

from __future__ import annotations

import copy
import html
from dataclasses import dataclass, field
from datetime import UTC, datetime
from io import BytesIO
from typing import Any

from weasyprint import CSS, HTML


@dataclass
class ReportMetadata:
    """Metadata for PDF report header."""

    company_name: str = "AuthTest Security Assessment"
    project_name: str = ""
    assessor_name: str = ""
    report_date: datetime = field(default_factory=lambda: datetime.now(UTC))
    confidentiality: str = "CONFIDENTIAL"
    include_tokens: bool = False  # Redact sensitive tokens by default


def redact_sensitive_data(data: dict[str, Any]) -> dict[str, Any]:
    """Redact sensitive token values from data.

    Args:
        data: The result data dictionary to redact

    Returns:
        A copy of the data with tokens redacted
    """
    redacted = copy.deepcopy(data)

    # Redact from response_data.tokens
    if redacted.get("response_data") and isinstance(redacted["response_data"], dict):
        tokens = redacted["response_data"].get("tokens")
        if tokens and isinstance(tokens, dict):
            for key in ["access_token", "id_token", "refresh_token"]:
                if key in tokens and tokens[key]:
                    # Show first/last few chars for identification
                    original = tokens[key]
                    if len(original) > 20:
                        tokens[key] = f"{original[:8]}...{original[-8:]} [REDACTED]"
                    else:
                        tokens[key] = "[REDACTED]"

    # Redact from request_data
    if redacted.get("request_data") and isinstance(redacted["request_data"], dict):
        for key in ["client_secret", "code_verifier"]:
            if key in redacted["request_data"]:
                redacted["request_data"][key] = "[REDACTED]"

    return redacted


def _format_timestamp(ts: datetime | str | None) -> str:
    """Format a timestamp for display."""
    if not ts:
        return "N/A"
    if isinstance(ts, str):
        return ts
    return ts.strftime("%Y-%m-%d %H:%M:%S UTC")


def _format_duration(ms: int | None) -> str:
    """Format duration in milliseconds."""
    if ms is None:
        return "N/A"
    if ms < 1000:
        return f"{ms}ms"
    return f"{ms / 1000:.2f}s"


def _escape(value: Any) -> str:
    """HTML escape a value."""
    if value is None:
        return ""
    return html.escape(str(value))


def _render_validation_checks(checks: list[dict[str, Any]]) -> str:
    """Render validation checks as HTML table rows."""
    if not checks:
        return "<tr><td colspan='4' class='empty'>No validation checks recorded</td></tr>"

    rows = []
    for check in checks:
        status = check.get("status", "unknown")
        status_class = {
            "valid": "status-valid",
            "invalid": "status-invalid",
            "warning": "status-warning",
            "skipped": "status-skipped",
        }.get(status, "")

        status_icon = {
            "valid": "✓",
            "invalid": "✗",
            "warning": "⚠",
            "skipped": "—",
        }.get(status, "?")

        rows.append(f"""
            <tr class="{status_class}">
                <td class="status-cell">{status_icon}</td>
                <td>{_escape(check.get('name', 'Unknown'))}</td>
                <td>{_escape(check.get('description', ''))}</td>
                <td>{_escape(check.get('message', ''))}</td>
            </tr>
        """)

    return "\n".join(rows)


def _render_claims_table(claims: dict[str, Any]) -> str:
    """Render claims as HTML table rows."""
    if not claims:
        return "<tr><td colspan='2' class='empty'>No claims available</td></tr>"

    rows = []
    for key, value in claims.items():
        if isinstance(value, (dict, list)):
            import json
            formatted_value = f"<pre>{_escape(json.dumps(value, indent=2))}</pre>"
        else:
            formatted_value = _escape(value)
        rows.append(f"""
            <tr>
                <td class="claim-name">{_escape(key)}</td>
                <td class="claim-value">{formatted_value}</td>
            </tr>
        """)

    return "\n".join(rows)


def _render_single_result(result: dict[str, Any], index: int) -> str:
    """Render a single test result as HTML section."""
    status = result.get("status", "unknown")
    status_class = {
        "passed": "status-passed",
        "failed": "status-failed",
        "error": "status-error",
    }.get(status, "")

    request_data = result.get("request_data", {}) or {}
    response_data = result.get("response_data", {}) or {}

    # Build request details
    request_html = ""
    if request_data:
        if request_data.get("authorization_url"):
            request_html += f'<p><strong>Authorization URL:</strong><br/><code class="url">{_escape(request_data["authorization_url"])}</code></p>'
        if request_data.get("client_id"):
            request_html += f'<p><strong>Client ID:</strong> <code>{_escape(request_data["client_id"])}</code></p>'
        if request_data.get("redirect_uri"):
            request_html += f'<p><strong>Redirect URI:</strong> <code>{_escape(request_data["redirect_uri"])}</code></p>'
        if request_data.get("scope"):
            scopes = request_data["scope"].split() if isinstance(request_data["scope"], str) else request_data["scope"]
            scope_badges = " ".join(f'<span class="scope-badge">{_escape(s)}</span>' for s in scopes)
            request_html += f'<p><strong>Scopes:</strong> {scope_badges}</p>'

    # Build tokens section
    tokens_html = ""
    tokens = response_data.get("tokens", {})
    if tokens:
        tokens_html = '<div class="tokens-section"><h4>Tokens Received</h4><div class="token-grid">'
        for token_type, label in [("access_token", "Access Token"), ("id_token", "ID Token"), ("refresh_token", "Refresh Token")]:
            if tokens.get(token_type):
                tokens_html += f'''
                    <div class="token-box">
                        <div class="token-label">{label}</div>
                        <code class="token-value">{_escape(tokens[token_type][:100])}{"..." if len(str(tokens[token_type])) > 100 else ""}</code>
                    </div>
                '''
        tokens_html += '</div></div>'

    # Build claims section
    claims_html = ""
    claims = response_data.get("claims", {})
    if claims:
        claims_html = f'''
            <div class="claims-section">
                <h4>Token Claims</h4>
                <table class="claims-table">
                    <thead>
                        <tr>
                            <th>Claim</th>
                            <th>Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        {_render_claims_table(claims)}
                    </tbody>
                </table>
            </div>
        '''

    # Build validation section
    validation_html = ""
    validation = response_data.get("validation", {})
    checks = validation.get("checks", []) if validation else []
    if checks:
        validation_html = f'''
            <div class="validation-section">
                <h4>Validation Results</h4>
                <table class="validation-table">
                    <thead>
                        <tr>
                            <th class="status-col">Status</th>
                            <th>Check</th>
                            <th>Description</th>
                            <th>Message</th>
                        </tr>
                    </thead>
                    <tbody>
                        {_render_validation_checks(checks)}
                    </tbody>
                </table>
            </div>
        '''

    # Build error section
    error_html = ""
    if result.get("error_message"):
        error_html = f'''
            <div class="error-section">
                <h4>Error Details</h4>
                <p class="error-message">{_escape(result["error_message"])}</p>
            </div>
        '''

    return f'''
        <div class="result-section">
            <div class="result-header {status_class}">
                <h3>Test #{index}: {_escape(result.get("test_name", "Unknown Test"))}</h3>
                <span class="status-badge">{status.upper()}</span>
            </div>

            <div class="result-meta">
                <table class="meta-table">
                    <tr>
                        <td><strong>Protocol:</strong></td>
                        <td><span class="protocol-badge">{_escape(result.get("test_type", "").upper())}</span></td>
                        <td><strong>IdP:</strong></td>
                        <td>{_escape(result.get("idp_name") or result.get("idp", {}).get("name") or "Unknown")}</td>
                    </tr>
                    <tr>
                        <td><strong>Started:</strong></td>
                        <td>{_format_timestamp(result.get("started_at"))}</td>
                        <td><strong>Duration:</strong></td>
                        <td>{_format_duration(result.get("duration_ms"))}</td>
                    </tr>
                </table>
            </div>

            {error_html}

            <div class="result-details">
                {f'<div class="request-section"><h4>Request Details</h4>{request_html}</div>' if request_html else ''}
                {tokens_html}
                {claims_html}
                {validation_html}
            </div>
        </div>
    '''


def generate_pdf_report(
    results: list[dict[str, Any]],
    metadata: ReportMetadata | None = None,
) -> bytes:
    """Generate a PDF report from test results.

    Args:
        results: List of test result dictionaries
        metadata: Optional report metadata for header

    Returns:
        PDF document as bytes
    """
    if metadata is None:
        metadata = ReportMetadata()

    # Redact sensitive data if requested
    if not metadata.include_tokens:
        results = [redact_sensitive_data(r) for r in results]

    # Calculate summary statistics
    total = len(results)
    passed = sum(1 for r in results if r.get("status") == "passed")
    failed = sum(1 for r in results if r.get("status") == "failed")
    errors = sum(1 for r in results if r.get("status") == "error")

    # Generate individual result sections
    result_sections = "\n".join(
        _render_single_result(r, i + 1) for i, r in enumerate(results)
    )

    # Build the full HTML document
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>AuthTest Security Assessment Report</title>
    </head>
    <body>
        <header class="report-header">
            <div class="header-content">
                <div class="logo-section">
                    <h1>AuthTest</h1>
                    <p class="subtitle">Authentication Security Assessment</p>
                </div>
                <div class="confidentiality-badge">{_escape(metadata.confidentiality)}</div>
            </div>

            <div class="report-info">
                <table>
                    <tr>
                        <td><strong>Company/Project:</strong></td>
                        <td>{_escape(metadata.company_name)}{f" - {_escape(metadata.project_name)}" if metadata.project_name else ""}</td>
                    </tr>
                    {f'<tr><td><strong>Assessor:</strong></td><td>{_escape(metadata.assessor_name)}</td></tr>' if metadata.assessor_name else ''}
                    <tr>
                        <td><strong>Report Date:</strong></td>
                        <td>{_format_timestamp(metadata.report_date)}</td>
                    </tr>
                    <tr>
                        <td><strong>Sensitive Data:</strong></td>
                        <td>{"Included" if metadata.include_tokens else "Redacted"}</td>
                    </tr>
                </table>
            </div>
        </header>

        <section class="summary-section">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card total">
                    <div class="summary-number">{total}</div>
                    <div class="summary-label">Total Tests</div>
                </div>
                <div class="summary-card passed">
                    <div class="summary-number">{passed}</div>
                    <div class="summary-label">Passed</div>
                </div>
                <div class="summary-card failed">
                    <div class="summary-number">{failed}</div>
                    <div class="summary-label">Failed</div>
                </div>
                <div class="summary-card errors">
                    <div class="summary-number">{errors}</div>
                    <div class="summary-label">Errors</div>
                </div>
            </div>
        </section>

        <section class="results-section">
            <h2>Test Results</h2>
            {result_sections if result_sections else '<p class="no-results">No test results to display.</p>'}
        </section>

        <footer class="report-footer">
            <p>Generated by AuthTest on {_format_timestamp(datetime.now(UTC))}</p>
            <p class="page-number">Page <span class="page"></span> of <span class="topage"></span></p>
        </footer>
    </body>
    </html>
    """

    # CSS for professional styling
    css = CSS(string="""
        @page {
            size: A4;
            margin: 2cm 1.5cm;

            @bottom-center {
                content: "Page " counter(page) " of " counter(pages);
                font-size: 9pt;
                color: #666;
            }
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            font-size: 10pt;
            line-height: 1.4;
            color: #333;
        }

        /* Header Styles */
        .report-header {
            border-bottom: 3px solid #2563eb;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }

        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }

        .logo-section h1 {
            font-size: 24pt;
            color: #1e40af;
            margin: 0;
        }

        .logo-section .subtitle {
            font-size: 12pt;
            color: #6b7280;
            margin: 5px 0 0 0;
        }

        .confidentiality-badge {
            background: #dc2626;
            color: white;
            padding: 5px 15px;
            font-size: 9pt;
            font-weight: bold;
            letter-spacing: 1px;
        }

        .report-info {
            margin-top: 20px;
        }

        .report-info table {
            width: 100%;
            font-size: 10pt;
        }

        .report-info td {
            padding: 3px 10px 3px 0;
        }

        /* Summary Section */
        .summary-section {
            margin-bottom: 30px;
        }

        .summary-section h2 {
            font-size: 16pt;
            color: #1e40af;
            border-bottom: 1px solid #e5e7eb;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }

        .summary-grid {
            display: flex;
            gap: 15px;
        }

        .summary-card {
            flex: 1;
            text-align: center;
            padding: 15px;
            border-radius: 8px;
        }

        .summary-card.total {
            background: #e0e7ff;
            border: 1px solid #6366f1;
        }

        .summary-card.passed {
            background: #d1fae5;
            border: 1px solid #10b981;
        }

        .summary-card.failed {
            background: #fee2e2;
            border: 1px solid #ef4444;
        }

        .summary-card.errors {
            background: #fef3c7;
            border: 1px solid #f59e0b;
        }

        .summary-number {
            font-size: 24pt;
            font-weight: bold;
            color: #1f2937;
        }

        .summary-label {
            font-size: 10pt;
            color: #6b7280;
            margin-top: 5px;
        }

        /* Results Section */
        .results-section h2 {
            font-size: 16pt;
            color: #1e40af;
            border-bottom: 1px solid #e5e7eb;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }

        .result-section {
            margin-bottom: 25px;
            page-break-inside: avoid;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            overflow: hidden;
        }

        .result-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 15px;
            background: #f9fafb;
        }

        .result-header.status-passed {
            background: #d1fae5;
            border-left: 4px solid #10b981;
        }

        .result-header.status-failed {
            background: #fee2e2;
            border-left: 4px solid #ef4444;
        }

        .result-header.status-error {
            background: #fef3c7;
            border-left: 4px solid #f59e0b;
        }

        .result-header h3 {
            margin: 0;
            font-size: 12pt;
            color: #1f2937;
        }

        .status-badge {
            padding: 3px 10px;
            font-size: 9pt;
            font-weight: bold;
            border-radius: 4px;
            background: white;
        }

        .result-meta {
            padding: 15px;
            background: #f9fafb;
            border-bottom: 1px solid #e5e7eb;
        }

        .meta-table {
            width: 100%;
            font-size: 9pt;
        }

        .meta-table td {
            padding: 3px 10px 3px 0;
        }

        .protocol-badge {
            background: #6366f1;
            color: white;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 8pt;
            font-weight: bold;
        }

        .result-details {
            padding: 15px;
        }

        .result-details h4 {
            font-size: 11pt;
            color: #374151;
            margin: 15px 0 10px 0;
            border-bottom: 1px solid #e5e7eb;
            padding-bottom: 5px;
        }

        .result-details h4:first-child {
            margin-top: 0;
        }

        /* Request Section */
        code {
            font-family: "SF Mono", Monaco, "Courier New", monospace;
            font-size: 8pt;
            background: #f3f4f6;
            padding: 2px 4px;
            border-radius: 3px;
        }

        code.url {
            display: block;
            word-break: break-all;
            padding: 8px;
            margin-top: 5px;
        }

        .scope-badge {
            display: inline-block;
            background: #e5e7eb;
            padding: 2px 6px;
            margin: 2px;
            border-radius: 3px;
            font-size: 8pt;
        }

        /* Tokens Section */
        .tokens-section {
            margin-top: 15px;
        }

        .token-grid {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }

        .token-box {
            flex: 1;
            min-width: 200px;
            background: #f9fafb;
            border: 1px solid #e5e7eb;
            border-radius: 6px;
            padding: 10px;
        }

        .token-label {
            font-size: 9pt;
            font-weight: bold;
            color: #6b7280;
            margin-bottom: 5px;
        }

        .token-value {
            font-size: 7pt;
            word-break: break-all;
            display: block;
            background: transparent;
            padding: 0;
        }

        /* Claims Table */
        .claims-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 9pt;
            margin-top: 10px;
        }

        .claims-table th,
        .claims-table td {
            border: 1px solid #e5e7eb;
            padding: 6px 10px;
            text-align: left;
        }

        .claims-table th {
            background: #f9fafb;
            font-weight: bold;
        }

        .claims-table .claim-name {
            width: 30%;
            font-weight: 500;
            color: #374151;
        }

        .claims-table pre {
            margin: 0;
            white-space: pre-wrap;
            font-size: 8pt;
        }

        /* Validation Table */
        .validation-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 9pt;
            margin-top: 10px;
        }

        .validation-table th,
        .validation-table td {
            border: 1px solid #e5e7eb;
            padding: 6px 10px;
            text-align: left;
        }

        .validation-table th {
            background: #f9fafb;
            font-weight: bold;
        }

        .validation-table .status-col {
            width: 50px;
            text-align: center;
        }

        .validation-table .status-cell {
            text-align: center;
            font-weight: bold;
        }

        .validation-table tr.status-valid {
            background: #d1fae5;
        }

        .validation-table tr.status-invalid {
            background: #fee2e2;
        }

        .validation-table tr.status-warning {
            background: #fef3c7;
        }

        .validation-table tr.status-skipped {
            background: #f3f4f6;
        }

        /* Error Section */
        .error-section {
            background: #fee2e2;
            border: 1px solid #fca5a5;
            border-radius: 6px;
            padding: 15px;
            margin: 15px 0;
        }

        .error-section h4 {
            color: #dc2626;
            margin: 0 0 10px 0;
            border: none;
            padding: 0;
        }

        .error-message {
            color: #7f1d1d;
            margin: 0;
        }

        /* Empty state */
        .empty, .no-results {
            color: #9ca3af;
            font-style: italic;
            text-align: center;
            padding: 20px;
        }

        /* Footer */
        .report-footer {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #e5e7eb;
            text-align: center;
            font-size: 9pt;
            color: #6b7280;
        }

        .report-footer p {
            margin: 5px 0;
        }
    """)

    # Generate PDF
    html_doc = HTML(string=html_content)
    pdf_buffer = BytesIO()
    html_doc.write_pdf(pdf_buffer, stylesheets=[css])

    return pdf_buffer.getvalue()


def generate_single_result_pdf(
    result: dict[str, Any],
    metadata: ReportMetadata | None = None,
) -> bytes:
    """Generate a PDF report for a single test result.

    Args:
        result: Test result dictionary
        metadata: Optional report metadata

    Returns:
        PDF document as bytes
    """
    return generate_pdf_report([result], metadata)
