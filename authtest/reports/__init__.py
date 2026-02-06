"""Report generation module for AuthTest.

Provides PDF, HTML, and other report formats for test results.
"""

from authtest.reports.html import (
    HTMLReportMetadata,
    generate_html_report,
    generate_single_result_html,
)
from authtest.reports.pdf import (
    ReportMetadata,
    generate_pdf_report,
    generate_single_result_pdf,
    redact_sensitive_data,
)

__all__ = [
    # PDF exports
    "ReportMetadata",
    "generate_pdf_report",
    "generate_single_result_pdf",
    "redact_sensitive_data",
    # HTML exports
    "HTMLReportMetadata",
    "generate_html_report",
    "generate_single_result_html",
]
