"""HTML report generator.

Generates standalone HTML reports from test results with:
- Self-contained HTML with embedded CSS
- Syntax highlighting for tokens and claims
- Interactive expand/collapse sections
- Works offline without external dependencies
"""

from __future__ import annotations

import copy
import html
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class HTMLReportMetadata:
    """Metadata for HTML report header."""

    company_name: str = "AuthTest Security Assessment"
    project_name: str = ""
    assessor_name: str = ""
    report_date: datetime = field(default_factory=lambda: datetime.now(UTC))
    include_tokens: bool = False  # Redact sensitive tokens by default


def _redact_tokens(data: dict[str, Any]) -> dict[str, Any]:
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


def _escape(value: Any) -> str:
    """HTML escape a value."""
    if value is None:
        return ""
    return html.escape(str(value))


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


def _format_json_highlighted(data: Any, indent: int = 2) -> str:
    """Format JSON with syntax highlighting.

    Returns HTML with span elements for syntax highlighting.
    """
    if data is None:
        return '<span class="json-null">null</span>'

    json_str = json.dumps(data, indent=indent, default=str)

    # Apply syntax highlighting
    highlighted = html.escape(json_str)

    # Highlight strings (including keys)
    import re
    highlighted = re.sub(
        r'("(?:[^"\\]|\\.)*")',
        r'<span class="json-string">\1</span>',
        highlighted
    )

    # Highlight numbers
    highlighted = re.sub(
        r'\b(-?\d+\.?\d*)\b',
        r'<span class="json-number">\1</span>',
        highlighted
    )

    # Highlight booleans
    highlighted = re.sub(
        r'\b(true|false)\b',
        r'<span class="json-boolean">\1</span>',
        highlighted
    )

    # Highlight null
    highlighted = re.sub(
        r'\b(null)\b',
        r'<span class="json-null">\1</span>',
        highlighted
    )

    return highlighted


def _render_validation_checks(checks: list[dict[str, Any]]) -> str:
    """Render validation checks as HTML."""
    if not checks:
        return '<p class="empty-message">No validation checks recorded</p>'

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
            "valid": "&#x2713;",  # ✓
            "invalid": "&#x2717;",  # ✗
            "warning": "&#x26A0;",  # ⚠
            "skipped": "&#x2014;",  # —
        }.get(status, "?")

        rows.append(f"""
            <tr class="{status_class}">
                <td class="status-cell">{status_icon}</td>
                <td>{_escape(check.get('name', 'Unknown'))}</td>
                <td>{_escape(check.get('description', ''))}</td>
                <td>{_escape(check.get('message', ''))}</td>
            </tr>
        """)

    return f"""
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
                {"".join(rows)}
            </tbody>
        </table>
    """


def _render_claims_table(claims: dict[str, Any]) -> str:
    """Render claims as HTML table."""
    if not claims:
        return '<p class="empty-message">No claims available</p>'

    rows = []
    for key, value in claims.items():
        if isinstance(value, (dict, list)):
            formatted_value = f'<pre class="json-block">{_format_json_highlighted(value)}</pre>'
        else:
            formatted_value = f'<code>{_escape(value)}</code>'
        rows.append(f"""
            <tr>
                <td class="claim-name">{_escape(key)}</td>
                <td class="claim-value">{formatted_value}</td>
            </tr>
        """)

    return f"""
        <table class="claims-table">
            <thead>
                <tr>
                    <th>Claim</th>
                    <th>Value</th>
                </tr>
            </thead>
            <tbody>
                {"".join(rows)}
            </tbody>
        </table>
    """


def _render_single_result(result: dict[str, Any], index: int) -> str:
    """Render a single test result as HTML section with collapsible content."""
    status = result.get("status", "unknown")
    status_class = {
        "passed": "status-passed",
        "failed": "status-failed",
        "error": "status-error",
    }.get(status, "")

    request_data = result.get("request_data", {}) or {}
    response_data = result.get("response_data", {}) or {}

    result_id = f"result-{index}"

    # Build request details section
    request_html = ""
    if request_data:
        request_items = []
        if request_data.get("authorization_url"):
            request_items.append(f'''
                <div class="detail-item">
                    <span class="detail-label">Authorization URL:</span>
                    <code class="url-value">{_escape(request_data["authorization_url"])}</code>
                </div>
            ''')
        if request_data.get("client_id"):
            request_items.append(f'''
                <div class="detail-item">
                    <span class="detail-label">Client ID:</span>
                    <code>{_escape(request_data["client_id"])}</code>
                </div>
            ''')
        if request_data.get("redirect_uri"):
            request_items.append(f'''
                <div class="detail-item">
                    <span class="detail-label">Redirect URI:</span>
                    <code>{_escape(request_data["redirect_uri"])}</code>
                </div>
            ''')
        if request_data.get("scope"):
            scopes = request_data["scope"].split() if isinstance(request_data["scope"], str) else request_data["scope"]
            scope_badges = " ".join(f'<span class="scope-badge">{_escape(s)}</span>' for s in scopes)
            request_items.append(f'''
                <div class="detail-item">
                    <span class="detail-label">Scopes:</span>
                    <span class="scopes">{scope_badges}</span>
                </div>
            ''')

        if request_items:
            request_html = f'''
                <div class="collapsible-section">
                    <button class="section-toggle" onclick="toggleSection('{result_id}-request')">
                        <span class="toggle-icon">&#x25BC;</span>
                        Request Details
                    </button>
                    <div id="{result_id}-request" class="section-content expanded">
                        {"".join(request_items)}
                        <details class="raw-data">
                            <summary>Raw Request Data</summary>
                            <pre class="json-block">{_format_json_highlighted(request_data)}</pre>
                        </details>
                    </div>
                </div>
            '''

    # Build tokens section
    tokens_html = ""
    tokens = response_data.get("tokens", {})
    if tokens:
        token_items = []
        for token_type, label in [("access_token", "Access Token"), ("id_token", "ID Token"), ("refresh_token", "Refresh Token")]:
            if tokens.get(token_type):
                token_value = tokens[token_type]
                truncated = len(str(token_value)) > 100
                display_value = token_value[:100] + ("..." if truncated else "")
                token_items.append(f'''
                    <div class="token-box">
                        <div class="token-label">{label}</div>
                        <code class="token-value">{_escape(display_value)}</code>
                        {"<details class='full-token'><summary>Show full token</summary><pre>" + _escape(token_value) + "</pre></details>" if truncated else ""}
                    </div>
                ''')

        if token_items:
            tokens_html = f'''
                <div class="collapsible-section">
                    <button class="section-toggle" onclick="toggleSection('{result_id}-tokens')">
                        <span class="toggle-icon">&#x25BC;</span>
                        Tokens Received
                    </button>
                    <div id="{result_id}-tokens" class="section-content expanded">
                        <div class="token-grid">
                            {"".join(token_items)}
                        </div>
                    </div>
                </div>
            '''

    # Build claims section
    claims_html = ""
    claims = response_data.get("claims", {})
    if claims:
        claims_html = f'''
            <div class="collapsible-section">
                <button class="section-toggle" onclick="toggleSection('{result_id}-claims')">
                    <span class="toggle-icon">&#x25BC;</span>
                    Token Claims ({len(claims)} claims)
                </button>
                <div id="{result_id}-claims" class="section-content expanded">
                    {_render_claims_table(claims)}
                </div>
            </div>
        '''

    # Build validation section
    validation_html = ""
    validation = response_data.get("validation", {})
    checks = validation.get("checks", []) if validation else []
    if checks:
        passed = sum(1 for c in checks if c.get("status") == "valid")
        failed = sum(1 for c in checks if c.get("status") == "invalid")
        warnings = sum(1 for c in checks if c.get("status") == "warning")

        summary_parts = []
        if passed:
            summary_parts.append(f'<span class="check-passed">{passed} passed</span>')
        if failed:
            summary_parts.append(f'<span class="check-failed">{failed} failed</span>')
        if warnings:
            summary_parts.append(f'<span class="check-warning">{warnings} warnings</span>')
        summary = ", ".join(summary_parts) if summary_parts else "No checks"

        validation_html = f'''
            <div class="collapsible-section">
                <button class="section-toggle" onclick="toggleSection('{result_id}-validation')">
                    <span class="toggle-icon">&#x25BC;</span>
                    Validation Results ({summary})
                </button>
                <div id="{result_id}-validation" class="section-content expanded">
                    {_render_validation_checks(checks)}
                </div>
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
        <div class="result-card" id="{result_id}">
            <div class="result-header {status_class}">
                <div class="result-title">
                    <h3>Test #{index}: {_escape(result.get("test_name", "Unknown Test"))}</h3>
                    <span class="status-badge {status_class}">{status.upper()}</span>
                </div>
                <div class="result-meta">
                    <span class="protocol-badge">{_escape((result.get("test_type") or "").upper())}</span>
                    <span class="meta-item">IdP: {_escape(result.get("idp_name") or result.get("idp", {}).get("name") or "Unknown")}</span>
                    <span class="meta-item">Started: {_format_timestamp(result.get("started_at"))}</span>
                    <span class="meta-item">Duration: {_format_duration(result.get("duration_ms"))}</span>
                </div>
            </div>

            <div class="result-body">
                {error_html}
                {request_html}
                {tokens_html}
                {claims_html}
                {validation_html}
            </div>
        </div>
    '''


def generate_html_report(
    results: list[dict[str, Any]],
    metadata: HTMLReportMetadata | None = None,
) -> str:
    """Generate a standalone HTML report from test results.

    Args:
        results: List of test result dictionaries
        metadata: Optional report metadata for header

    Returns:
        Self-contained HTML document as string
    """
    if metadata is None:
        metadata = HTMLReportMetadata()

    # Redact sensitive data if requested
    if not metadata.include_tokens:
        results = [_redact_tokens(r) for r in results]

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
    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AuthTest Security Assessment Report</title>
    <style>
        /* === Reset & Base Styles === */
        *, *::before, *::after {{
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            font-size: 14px;
            line-height: 1.5;
            color: #1f2937;
            background-color: #f3f4f6;
            margin: 0;
            padding: 20px;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        /* === Header Styles === */
        .report-header {{
            background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
            color: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 24px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}

        .header-top {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 16px;
        }}

        .logo-section h1 {{
            font-size: 28px;
            margin: 0;
            font-weight: 700;
        }}

        .logo-section .subtitle {{
            font-size: 14px;
            opacity: 0.9;
            margin-top: 4px;
        }}

        .confidentiality-badge {{
            background: #dc2626;
            color: white;
            padding: 6px 16px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 1px;
            border-radius: 4px;
        }}

        .report-info {{
            margin-top: 24px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
        }}

        .info-item {{
            font-size: 13px;
        }}

        .info-item strong {{
            opacity: 0.9;
        }}

        /* === Summary Section === */
        .summary-section {{
            background: white;
            padding: 24px;
            border-radius: 12px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }}

        .summary-section h2 {{
            font-size: 20px;
            margin: 0 0 20px 0;
            color: #1e40af;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 16px;
        }}

        .summary-card {{
            text-align: center;
            padding: 20px;
            border-radius: 8px;
        }}

        .summary-card.total {{
            background: #e0e7ff;
            border: 1px solid #6366f1;
        }}

        .summary-card.passed {{
            background: #d1fae5;
            border: 1px solid #10b981;
        }}

        .summary-card.failed {{
            background: #fee2e2;
            border: 1px solid #ef4444;
        }}

        .summary-card.errors {{
            background: #fef3c7;
            border: 1px solid #f59e0b;
        }}

        .summary-number {{
            font-size: 32px;
            font-weight: 700;
            color: #1f2937;
        }}

        .summary-label {{
            font-size: 13px;
            color: #6b7280;
            margin-top: 4px;
        }}

        /* === Results Section === */
        .results-section {{
            margin-bottom: 24px;
        }}

        .results-section h2 {{
            font-size: 20px;
            margin: 0 0 20px 0;
            color: #1e40af;
        }}

        /* === Result Card === */
        .result-card {{
            background: white;
            border-radius: 12px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }}

        .result-header {{
            padding: 16px 20px;
            border-left: 4px solid #9ca3af;
        }}

        .result-header.status-passed {{
            background: #d1fae5;
            border-left-color: #10b981;
        }}

        .result-header.status-failed {{
            background: #fee2e2;
            border-left-color: #ef4444;
        }}

        .result-header.status-error {{
            background: #fef3c7;
            border-left-color: #f59e0b;
        }}

        .result-title {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
        }}

        .result-title h3 {{
            margin: 0;
            font-size: 16px;
            color: #1f2937;
        }}

        .status-badge {{
            padding: 4px 12px;
            font-size: 11px;
            font-weight: 700;
            border-radius: 4px;
            background: white;
        }}

        .status-badge.status-passed {{
            color: #059669;
        }}

        .status-badge.status-failed {{
            color: #dc2626;
        }}

        .status-badge.status-error {{
            color: #d97706;
        }}

        .result-meta {{
            margin-top: 12px;
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            font-size: 13px;
            color: #4b5563;
        }}

        .protocol-badge {{
            background: #6366f1;
            color: white;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
        }}

        .result-body {{
            padding: 20px;
        }}

        /* === Collapsible Sections === */
        .collapsible-section {{
            margin-bottom: 16px;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            overflow: hidden;
        }}

        .section-toggle {{
            width: 100%;
            padding: 12px 16px;
            background: #f9fafb;
            border: none;
            text-align: left;
            font-size: 14px;
            font-weight: 600;
            color: #374151;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: background 0.2s;
        }}

        .section-toggle:hover {{
            background: #f3f4f6;
        }}

        .toggle-icon {{
            font-size: 10px;
            transition: transform 0.2s;
        }}

        .section-content {{
            padding: 16px;
            display: none;
        }}

        .section-content.expanded {{
            display: block;
        }}

        .section-toggle.collapsed .toggle-icon {{
            transform: rotate(-90deg);
        }}

        /* === Detail Items === */
        .detail-item {{
            margin-bottom: 12px;
        }}

        .detail-label {{
            display: block;
            font-size: 12px;
            font-weight: 600;
            color: #6b7280;
            margin-bottom: 4px;
        }}

        .url-value {{
            display: block;
            word-break: break-all;
            padding: 8px;
            background: #f3f4f6;
            border-radius: 4px;
            font-size: 12px;
        }}

        code {{
            font-family: "SF Mono", Monaco, "Courier New", monospace;
            font-size: 12px;
            background: #f3f4f6;
            padding: 2px 6px;
            border-radius: 4px;
        }}

        .scope-badge {{
            display: inline-block;
            background: #e5e7eb;
            padding: 2px 8px;
            margin: 2px;
            border-radius: 4px;
            font-size: 12px;
        }}

        /* === Token Display === */
        .token-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 12px;
        }}

        .token-box {{
            background: #f9fafb;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 12px;
        }}

        .token-label {{
            font-size: 12px;
            font-weight: 600;
            color: #6b7280;
            margin-bottom: 6px;
        }}

        .token-value {{
            font-size: 11px;
            word-break: break-all;
            display: block;
            background: transparent;
            padding: 0;
        }}

        .full-token {{
            margin-top: 8px;
        }}

        .full-token summary {{
            font-size: 11px;
            color: #3b82f6;
            cursor: pointer;
        }}

        .full-token pre {{
            margin: 8px 0 0 0;
            padding: 8px;
            background: #1f2937;
            color: #e5e7eb;
            border-radius: 4px;
            font-size: 10px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }}

        /* === Tables === */
        .claims-table, .validation-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}

        .claims-table th,
        .claims-table td,
        .validation-table th,
        .validation-table td {{
            border: 1px solid #e5e7eb;
            padding: 10px 12px;
            text-align: left;
        }}

        .claims-table th,
        .validation-table th {{
            background: #f9fafb;
            font-weight: 600;
            color: #374151;
        }}

        .claims-table .claim-name {{
            width: 30%;
            font-weight: 500;
            color: #374151;
        }}

        .validation-table .status-col {{
            width: 60px;
            text-align: center;
        }}

        .validation-table .status-cell {{
            text-align: center;
            font-weight: bold;
            font-size: 16px;
        }}

        .validation-table tr.status-valid {{
            background: #d1fae5;
        }}

        .validation-table tr.status-invalid {{
            background: #fee2e2;
        }}

        .validation-table tr.status-warning {{
            background: #fef3c7;
        }}

        .validation-table tr.status-skipped {{
            background: #f3f4f6;
        }}

        /* === Check Summary === */
        .check-passed {{
            color: #059669;
            font-weight: 600;
        }}

        .check-failed {{
            color: #dc2626;
            font-weight: 600;
        }}

        .check-warning {{
            color: #d97706;
            font-weight: 600;
        }}

        /* === JSON Syntax Highlighting === */
        .json-block {{
            background: #1f2937;
            color: #e5e7eb;
            padding: 12px;
            border-radius: 6px;
            font-family: "SF Mono", Monaco, "Courier New", monospace;
            font-size: 12px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-word;
            margin: 8px 0;
        }}

        .json-string {{
            color: #a5d6ff;
        }}

        .json-number {{
            color: #79c0ff;
        }}

        .json-boolean {{
            color: #ff7b72;
        }}

        .json-null {{
            color: #ff7b72;
        }}

        /* === Raw Data Disclosure === */
        .raw-data {{
            margin-top: 12px;
        }}

        .raw-data summary {{
            font-size: 12px;
            color: #6b7280;
            cursor: pointer;
            padding: 4px 0;
        }}

        .raw-data summary:hover {{
            color: #3b82f6;
        }}

        /* === Error Section === */
        .error-section {{
            background: #fee2e2;
            border: 1px solid #fca5a5;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 16px;
        }}

        .error-section h4 {{
            color: #dc2626;
            margin: 0 0 8px 0;
            font-size: 14px;
        }}

        .error-message {{
            color: #7f1d1d;
            margin: 0;
        }}

        /* === Empty State === */
        .empty-message {{
            color: #9ca3af;
            font-style: italic;
            text-align: center;
            padding: 20px;
        }}

        .no-results {{
            background: white;
            border-radius: 12px;
            padding: 40px;
            text-align: center;
            color: #6b7280;
        }}

        /* === Footer === */
        .report-footer {{
            text-align: center;
            padding: 24px;
            color: #6b7280;
            font-size: 12px;
        }}

        .report-footer a {{
            color: #3b82f6;
            text-decoration: none;
        }}

        /* === Controls === */
        .controls {{
            display: flex;
            justify-content: flex-end;
            gap: 8px;
            margin-bottom: 16px;
        }}

        .control-btn {{
            padding: 8px 16px;
            font-size: 12px;
            border: 1px solid #d1d5db;
            background: white;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s;
        }}

        .control-btn:hover {{
            background: #f9fafb;
            border-color: #9ca3af;
        }}

        /* === Print Styles === */
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}

            .report-header {{
                background: #1e40af !important;
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }}

            .controls {{
                display: none;
            }}

            .section-content {{
                display: block !important;
            }}

            .result-card {{
                break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header class="report-header">
            <div class="header-top">
                <div class="logo-section">
                    <h1>AuthTest</h1>
                    <p class="subtitle">Authentication Security Assessment Report</p>
                </div>
                <div class="confidentiality-badge">CONFIDENTIAL</div>
            </div>

            <div class="report-info">
                <div class="info-item">
                    <strong>Company/Project:</strong>
                    {_escape(metadata.company_name)}{f" - {_escape(metadata.project_name)}" if metadata.project_name else ""}
                </div>
                {f'<div class="info-item"><strong>Assessor:</strong> {_escape(metadata.assessor_name)}</div>' if metadata.assessor_name else ''}
                <div class="info-item">
                    <strong>Report Date:</strong> {_format_timestamp(metadata.report_date)}
                </div>
                <div class="info-item">
                    <strong>Sensitive Data:</strong> {"Included" if metadata.include_tokens else "Redacted"}
                </div>
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

            <div class="controls">
                <button class="control-btn" onclick="expandAll()">Expand All</button>
                <button class="control-btn" onclick="collapseAll()">Collapse All</button>
                <button class="control-btn" onclick="window.print()">Print Report</button>
            </div>

            {result_sections if result_sections else '<div class="no-results">No test results to display.</div>'}
        </section>

        <footer class="report-footer">
            <p>Generated by <strong>AuthTest</strong> on {_format_timestamp(datetime.now(UTC))}</p>
            <p>This report is self-contained and works offline.</p>
        </footer>
    </div>

    <script>
        // Toggle individual section
        function toggleSection(sectionId) {{
            const section = document.getElementById(sectionId);
            const button = section.previousElementSibling;

            if (section.classList.contains('expanded')) {{
                section.classList.remove('expanded');
                button.classList.add('collapsed');
            }} else {{
                section.classList.add('expanded');
                button.classList.remove('collapsed');
            }}
        }}

        // Expand all sections
        function expandAll() {{
            document.querySelectorAll('.section-content').forEach(section => {{
                section.classList.add('expanded');
            }});
            document.querySelectorAll('.section-toggle').forEach(button => {{
                button.classList.remove('collapsed');
            }});
        }}

        // Collapse all sections
        function collapseAll() {{
            document.querySelectorAll('.section-content').forEach(section => {{
                section.classList.remove('expanded');
            }});
            document.querySelectorAll('.section-toggle').forEach(button => {{
                button.classList.add('collapsed');
            }});
        }}
    </script>
</body>
</html>'''

    return html_content


def generate_single_result_html(
    result: dict[str, Any],
    metadata: HTMLReportMetadata | None = None,
) -> str:
    """Generate an HTML report for a single test result.

    Args:
        result: Test result dictionary
        metadata: Optional report metadata

    Returns:
        Self-contained HTML document as string
    """
    return generate_html_report([result], metadata)
