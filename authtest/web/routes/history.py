"""Test history management web routes."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from flask import (
    Blueprint,
    Response,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

if TYPE_CHECKING:
    from werkzeug.wrappers import Response as WerkzeugResponse

from authtest.storage.database import get_database
from authtest.storage.models import IdPProvider, TestResult


def _redact_tokens_from_data(data: dict[str, Any]) -> dict[str, Any]:
    """Redact sensitive token values from export data.

    Args:
        data: The result data dictionary to redact

    Returns:
        A copy of the data with tokens redacted
    """
    import copy
    redacted = copy.deepcopy(data)

    # Redact from response_data.tokens
    if redacted.get("response_data") and isinstance(redacted["response_data"], dict):
        tokens = redacted["response_data"].get("tokens")
        if tokens and isinstance(tokens, dict):
            for key in ["access_token", "id_token", "refresh_token"]:
                if key in tokens and tokens[key]:
                    tokens[key] = "[REDACTED]"

    # Redact from request_data (e.g., client_secret if present)
    if redacted.get("request_data") and isinstance(redacted["request_data"], dict):
        for key in ["client_secret", "code_verifier"]:
            if key in redacted["request_data"]:
                redacted["request_data"][key] = "[REDACTED]"

    return redacted

# Get the directories relative to this package
_web_dir = Path(__file__).parent.parent
_templates_dir = _web_dir / "templates"

history_bp = Blueprint(
    "history",
    __name__,
    template_folder=str(_templates_dir),
    url_prefix="/history",
)


def _parse_date_or_duration(value: str, end_of_day: bool = False) -> datetime | None:
    """Parse a date string or duration.

    Args:
        value: Either a date (YYYY-MM-DD) or duration (e.g., '7d', '24h')
        end_of_day: If True and parsing a date, return end of day instead of start

    Returns:
        datetime object or None if parsing fails
    """
    if not value:
        return None

    # Try duration format first (e.g., '7d', '24h', '30m')
    if value[-1] in "dhm":
        try:
            num = int(value[:-1])
            unit = value[-1]
            now = datetime.now(UTC)
            if unit == "d":
                return now - timedelta(days=num)
            elif unit == "h":
                return now - timedelta(hours=num)
            elif unit == "m":
                return now - timedelta(minutes=num)
        except ValueError:
            pass

    # Try date format (YYYY-MM-DD)
    try:
        dt = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=UTC)
        if end_of_day:
            dt = dt.replace(hour=23, minute=59, second=59)
        return dt
    except ValueError:
        pass

    return None


@history_bp.route("/")
def index() -> str:
    """Test history browser with filters."""
    db = get_database()
    db_session = db.get_session()

    try:
        # Get filter parameters
        idp_name = request.args.get("idp", "")
        test_type = request.args.get("type", "")
        test_status = request.args.get("status", "")
        since = request.args.get("since", "")
        until = request.args.get("until", "")
        search = request.args.get("search", "")
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 20, type=int)

        # Parse date filters
        since_dt = _parse_date_or_duration(since) if since else None
        until_dt = _parse_date_or_duration(until, end_of_day=True) if until else None

        # Build query
        query = db_session.query(TestResult)

        # Apply filters
        if idp_name:
            query = query.join(IdPProvider).filter(IdPProvider.name == idp_name)

        if test_type:
            query = query.filter(TestResult.test_type == test_type)

        if test_status:
            query = query.filter(TestResult.status == test_status)

        if since_dt:
            query = query.filter(TestResult.started_at >= since_dt)

        if until_dt:
            query = query.filter(TestResult.started_at <= until_dt)

        if search:
            query = query.filter(TestResult.test_name.ilike(f"%{search}%"))

        # Get total count
        total = query.count()

        # Calculate pagination
        total_pages = (total + per_page - 1) // per_page
        offset = (page - 1) * per_page

        # Get results
        results = (
            query.order_by(TestResult.started_at.desc())
            .offset(offset)
            .limit(per_page)
            .all()
        )

        # Get all IdPs for filter dropdown
        idps = db_session.query(IdPProvider).order_by(IdPProvider.name).all()

        # Get statistics
        stats = {
            "total": db_session.query(TestResult).count(),
            "passed": db_session.query(TestResult).filter(TestResult.status == "passed").count(),
            "failed": db_session.query(TestResult).filter(TestResult.status == "failed").count(),
            "error": db_session.query(TestResult).filter(TestResult.status == "error").count(),
        }

        return render_template(
            "history/index.html",
            results=results,
            idps=idps,
            stats=stats,
            filters={
                "idp": idp_name,
                "type": test_type,
                "status": test_status,
                "since": since,
                "until": until,
                "search": search,
            },
            pagination={
                "page": page,
                "per_page": per_page,
                "total": total,
                "total_pages": total_pages,
            },
        )
    finally:
        db_session.close()


@history_bp.route("/<int:test_id>")
def show(test_id: int) -> str | WerkzeugResponse:
    """Show detailed view of a test result."""
    db = get_database()
    db_session = db.get_session()

    try:
        result = db_session.query(TestResult).get(test_id)
        if not result:
            flash("Test result not found", "error")
            return redirect(url_for("history.index"))

        return render_template(
            "history/show.html",
            result=result,
        )
    finally:
        db_session.close()


@history_bp.route("/export", methods=["GET", "POST"])
def export() -> str | Response | WerkzeugResponse:
    """Export test results."""
    db = get_database()
    db_session = db.get_session()

    try:
        if request.method == "GET":
            # Show export form
            idps = db_session.query(IdPProvider).order_by(IdPProvider.name).all()
            total_count = db_session.query(TestResult).count()
            return render_template(
                "history/export.html",
                idps=idps,
                total_count=total_count,
            )

        # POST - perform export
        idp_name = request.form.get("idp", "")
        test_type = request.form.get("type", "")
        test_status = request.form.get("status", "")
        since = request.form.get("since", "")
        until = request.form.get("until", "")
        export_format = request.form.get("format", "json")
        selected_ids = request.form.get("selected_ids", "")
        include_tokens = request.form.get("include_tokens", "true") == "true"

        # Parse date filters
        since_dt = _parse_date_or_duration(since) if since else None
        until_dt = _parse_date_or_duration(until, end_of_day=True) if until else None

        # Build query
        query = db_session.query(TestResult)

        # Filter by selected IDs if provided
        if selected_ids:
            id_list = [int(x.strip()) for x in selected_ids.split(",") if x.strip()]
            if id_list:
                query = query.filter(TestResult.id.in_(id_list))
        else:
            # Apply other filters
            if idp_name:
                query = query.join(IdPProvider).filter(IdPProvider.name == idp_name)

            if test_type:
                query = query.filter(TestResult.test_type == test_type)

            if test_status:
                query = query.filter(TestResult.status == test_status)

            if since_dt:
                query = query.filter(TestResult.started_at >= since_dt)

            if until_dt:
                query = query.filter(TestResult.started_at <= until_dt)

        # Get results
        results = query.order_by(TestResult.started_at.desc()).all()

        if not results:
            flash("No results found to export", "error")
            return redirect(url_for("history.export"))

        # Format data
        export_data = []
        for r in results:
            result_dict: dict[str, Any] = {
                "id": r.id,
                "test_name": r.test_name,
                "test_type": r.test_type,
                "idp_name": r.idp_provider.name if r.idp_provider else None,
                "status": r.status,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                "duration_ms": r.duration_ms,
                "error_message": r.error_message,
                "error_details": r.error_details,
                "request_data": r.request_data,
                "response_data": r.response_data,
            }
            # Redact tokens if requested
            if not include_tokens:
                result_dict = _redact_tokens_from_data(result_dict)
            export_data.append(result_dict)

        # Generate response based on format
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

        if export_format == "json":
            content = json.dumps({
                "exported_at": datetime.now(UTC).isoformat(),
                "count": len(export_data),
                "results": export_data,
            }, indent=2, default=str)
            return Response(
                content,
                mimetype="application/json",
                headers={"Content-Disposition": f"attachment; filename=authtest_history_{timestamp}.json"},
            )
        elif export_format == "csv":
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=[
                "id", "test_name", "test_type", "idp_name", "status",
                "started_at", "completed_at", "duration_ms", "error_message",
            ])
            writer.writeheader()
            for row in export_data:
                csv_row = {k: v for k, v in row.items() if k not in ["error_details", "request_data", "response_data"]}
                writer.writerow(csv_row)

            return Response(
                output.getvalue(),
                mimetype="text/csv",
                headers={"Content-Disposition": f"attachment; filename=authtest_history_{timestamp}.csv"},
            )
        elif export_format == "pdf":
            from authtest.reports import ReportMetadata, generate_pdf_report

            # Get PDF-specific form fields
            company_name = request.form.get("company_name", "")
            project_name = request.form.get("project_name", "")
            assessor_name = request.form.get("assessor_name", "")

            metadata = ReportMetadata(
                company_name=company_name or "AuthTest Security Assessment",
                project_name=project_name,
                assessor_name=assessor_name,
                include_tokens=include_tokens,
            )
            pdf_bytes = generate_pdf_report(export_data, metadata)

            return Response(
                pdf_bytes,
                mimetype="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=authtest_report_{timestamp}.pdf"},
            )
        else:  # html
            from authtest.reports import HTMLReportMetadata, generate_html_report

            # Get HTML-specific form fields
            company_name = request.form.get("company_name", "")
            project_name = request.form.get("project_name", "")
            assessor_name = request.form.get("assessor_name", "")

            html_metadata = HTMLReportMetadata(
                company_name=company_name or "AuthTest Security Assessment",
                project_name=project_name,
                assessor_name=assessor_name,
                include_tokens=include_tokens,
            )
            html_content = generate_html_report(export_data, html_metadata)

            return Response(
                html_content,
                mimetype="text/html",
                headers={"Content-Disposition": f"attachment; filename=authtest_report_{timestamp}.html"},
            )
    finally:
        db_session.close()


@history_bp.route("/delete", methods=["POST"])
def delete() -> WerkzeugResponse:
    """Delete test results (bulk or single)."""
    db = get_database()
    db_session = db.get_session()

    try:
        # Get IDs to delete
        selected_ids = request.form.get("selected_ids", "")
        single_id = request.form.get("id", "")

        if single_id:
            id_list = [int(single_id)]
        elif selected_ids:
            id_list = [int(x.strip()) for x in selected_ids.split(",") if x.strip()]
        else:
            flash("No test results selected for deletion", "error")
            return redirect(url_for("history.index"))

        # Delete results
        deleted = (
            db_session.query(TestResult)
            .filter(TestResult.id.in_(id_list))
            .delete(synchronize_session="fetch")
        )
        db_session.commit()

        flash(f"Deleted {deleted} test result(s)", "success")
        return redirect(url_for("history.index"))
    finally:
        db_session.close()


@history_bp.route("/bulk-delete", methods=["POST"])
def bulk_delete() -> WerkzeugResponse:
    """Delete test results with filters (for bulk operations)."""
    db = get_database()
    db_session = db.get_session()

    try:
        # Get filter parameters
        idp_name = request.form.get("idp", "")
        test_type = request.form.get("type", "")
        test_status = request.form.get("status", "")
        before = request.form.get("before", "")
        delete_all = request.form.get("delete_all", "")

        # Build query
        query = db_session.query(TestResult)

        if delete_all != "true":
            # Apply filters
            if idp_name:
                query = query.join(IdPProvider).filter(IdPProvider.name == idp_name)

            if test_type:
                query = query.filter(TestResult.test_type == test_type)

            if test_status:
                query = query.filter(TestResult.status == test_status)

            if before:
                before_dt = _parse_date_or_duration(before, end_of_day=True)
                if before_dt:
                    query = query.filter(TestResult.started_at <= before_dt)

        # Count and delete
        count = query.count()
        if count == 0:
            flash("No test results found matching criteria", "info")
            return redirect(url_for("history.index"))

        deleted = query.delete(synchronize_session="fetch")
        db_session.commit()

        flash(f"Deleted {deleted} test result(s)", "success")
        return redirect(url_for("history.index"))
    finally:
        db_session.close()


@history_bp.route("/api/results")
def api_results() -> Response:
    """API endpoint for fetching results (used by JavaScript for dynamic updates)."""
    db = get_database()
    db_session = db.get_session()

    try:
        # Get filter parameters
        idp_name = request.args.get("idp", "")
        test_type = request.args.get("type", "")
        test_status = request.args.get("status", "")
        since = request.args.get("since", "")
        until = request.args.get("until", "")
        search = request.args.get("search", "")
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 20, type=int)

        # Parse date filters
        since_dt = _parse_date_or_duration(since) if since else None
        until_dt = _parse_date_or_duration(until, end_of_day=True) if until else None

        # Build query
        query = db_session.query(TestResult)

        # Apply filters
        if idp_name:
            query = query.join(IdPProvider).filter(IdPProvider.name == idp_name)

        if test_type:
            query = query.filter(TestResult.test_type == test_type)

        if test_status:
            query = query.filter(TestResult.status == test_status)

        if since_dt:
            query = query.filter(TestResult.started_at >= since_dt)

        if until_dt:
            query = query.filter(TestResult.started_at <= until_dt)

        if search:
            query = query.filter(TestResult.test_name.ilike(f"%{search}%"))

        # Get total count
        total = query.count()

        # Calculate pagination
        offset = (page - 1) * per_page

        # Get results
        results = (
            query.order_by(TestResult.started_at.desc())
            .offset(offset)
            .limit(per_page)
            .all()
        )

        # Format response
        data: list[dict[str, Any]] = []
        for r in results:
            data.append({
                "id": r.id,
                "test_name": r.test_name,
                "test_type": r.test_type,
                "idp_name": r.idp_provider.name if r.idp_provider else None,
                "status": r.status,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "duration_ms": r.duration_ms,
                "error_message": r.error_message,
            })

        return Response(
            json.dumps({
                "total": total,
                "page": page,
                "per_page": per_page,
                "results": data,
            }, default=str),
            mimetype="application/json",
        )
    finally:
        db_session.close()
