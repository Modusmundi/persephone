"""Report generation module for AuthTest.

Provides PDF and other report formats for test results.
"""

from authtest.reports.pdf import (
    ReportMetadata,
    generate_pdf_report,
    generate_single_result_pdf,
    redact_sensitive_data,
)

__all__ = [
    "ReportMetadata",
    "generate_pdf_report",
    "generate_single_result_pdf",
    "redact_sensitive_data",
]
