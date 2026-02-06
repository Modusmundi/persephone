"""Test comparison web routes."""

from __future__ import annotations

import json
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

from authtest.reports import compare_test_results, compare_with_baseline
from authtest.storage.database import get_database
from authtest.storage.models import IdPProvider, TestResult

# Get the directories relative to this package
_web_dir = Path(__file__).parent.parent
_templates_dir = _web_dir / "templates"

compare_bp = Blueprint(
    "compare",
    __name__,
    template_folder=str(_templates_dir),
    url_prefix="/compare",
)


@compare_bp.route("/")
def index() -> str:
    """Test comparison tool selection page."""
    db = get_database()
    db_session = db.get_session()

    try:
        # Get recent test results for selection
        results = (
            db_session.query(TestResult)
            .order_by(TestResult.started_at.desc())
            .limit(50)
            .all()
        )

        # Get all IdPs for filtering
        idps = db_session.query(IdPProvider).order_by(IdPProvider.name).all()

        return render_template(
            "compare/index.html",
            results=results,
            idps=idps,
        )
    finally:
        db_session.close()


@compare_bp.route("/diff")
def diff() -> str | WerkzeugResponse:
    """Side-by-side diff comparison between two test results."""
    db = get_database()
    db_session = db.get_session()

    try:
        baseline_id = request.args.get("baseline", type=int)
        comparison_id = request.args.get("comparison", type=int)
        show_unchanged = request.args.get("show_unchanged", "false") == "true"

        if not baseline_id or not comparison_id:
            flash("Please select both a baseline and comparison test result.", "error")
            return redirect(url_for("compare.index"))

        if baseline_id == comparison_id:
            flash("Baseline and comparison must be different test results.", "error")
            return redirect(url_for("compare.index"))

        # Load both test results
        baseline = db_session.query(TestResult).get(baseline_id)
        comparison_result = db_session.query(TestResult).get(comparison_id)

        if not baseline:
            flash(f"Baseline test result #{baseline_id} not found.", "error")
            return redirect(url_for("compare.index"))

        if not comparison_result:
            flash(f"Comparison test result #{comparison_id} not found.", "error")
            return redirect(url_for("compare.index"))

        # Convert to dictionaries for comparison
        baseline_dict = _result_to_dict(baseline)
        comparison_dict = _result_to_dict(comparison_result)

        # Perform comparison
        comparison = compare_test_results(baseline_dict, comparison_dict)

        return render_template(
            "compare/diff.html",
            baseline=baseline,
            comparison=comparison_result,
            diff=comparison,
            show_unchanged=show_unchanged,
        )
    finally:
        db_session.close()


@compare_bp.route("/baseline")
def baseline() -> str | WerkzeugResponse:
    """Baseline comparison mode - compare multiple tests against one baseline."""
    db = get_database()
    db_session = db.get_session()

    try:
        baseline_id = request.args.get("baseline", type=int)
        idp_name = request.args.get("idp", "")
        test_type = request.args.get("type", "")
        limit = request.args.get("limit", 10, type=int)
        regressions_only = request.args.get("regressions_only", "false") == "true"

        if not baseline_id:
            # Show baseline selection form
            results = (
                db_session.query(TestResult)
                .order_by(TestResult.started_at.desc())
                .limit(50)
                .all()
            )
            idps = db_session.query(IdPProvider).order_by(IdPProvider.name).all()

            return render_template(
                "compare/baseline_select.html",
                results=results,
                idps=idps,
            )

        # Load baseline
        baseline = db_session.query(TestResult).get(baseline_id)
        if not baseline:
            flash(f"Baseline test result #{baseline_id} not found.", "error")
            return redirect(url_for("compare.baseline"))

        baseline_dict = _result_to_dict(baseline)

        # Build query for comparison tests
        query = db_session.query(TestResult).filter(TestResult.id != baseline_id)

        if idp_name:
            query = query.join(IdPProvider).filter(IdPProvider.name == idp_name)
        elif baseline.idp_provider_id:
            query = query.filter(TestResult.idp_provider_id == baseline.idp_provider_id)

        if test_type:
            query = query.filter(TestResult.test_type == test_type)
        else:
            query = query.filter(TestResult.test_type == baseline.test_type)

        # Get results
        results = query.order_by(TestResult.started_at.desc()).limit(limit).all()

        # Convert and compare
        comparison_dicts = [_result_to_dict(r) for r in results]
        comparisons = compare_with_baseline(baseline_dict, comparison_dicts)

        # Filter by regressions if requested
        if regressions_only:
            comparisons = [c for c in comparisons if c.has_regressions]

        # Get IdPs for filter dropdown
        idps = db_session.query(IdPProvider).order_by(IdPProvider.name).all()

        return render_template(
            "compare/baseline.html",
            baseline=baseline,
            comparisons=comparisons,
            results=results,
            idps=idps,
            filters={
                "idp": idp_name,
                "type": test_type,
                "limit": limit,
                "regressions_only": regressions_only,
            },
            regression_count=sum(1 for c in comparisons if c.has_regressions),
        )
    finally:
        db_session.close()


@compare_bp.route("/api/results")
def api_results() -> Response:
    """API endpoint for fetching test results (for dynamic selection)."""
    db = get_database()
    db_session = db.get_session()

    try:
        idp_name = request.args.get("idp", "")
        test_type = request.args.get("type", "")
        limit = request.args.get("limit", 50, type=int)

        query = db_session.query(TestResult)

        if idp_name:
            query = query.join(IdPProvider).filter(IdPProvider.name == idp_name)

        if test_type:
            query = query.filter(TestResult.test_type == test_type)

        results = query.order_by(TestResult.started_at.desc()).limit(limit).all()

        data: list[dict[str, Any]] = []
        for r in results:
            data.append({
                "id": r.id,
                "test_name": r.test_name,
                "test_type": r.test_type,
                "idp_name": r.idp_provider.name if r.idp_provider else None,
                "status": r.status,
                "started_at": r.started_at.isoformat() if r.started_at else None,
            })

        return Response(
            json.dumps({"results": data}, default=str),
            mimetype="application/json",
        )
    finally:
        db_session.close()


@compare_bp.route("/api/diff")
def api_diff() -> Response:
    """API endpoint for comparing two test results."""
    db = get_database()
    db_session = db.get_session()

    try:
        baseline_id = request.args.get("baseline", type=int)
        comparison_id = request.args.get("comparison", type=int)

        if not baseline_id or not comparison_id:
            return Response(
                json.dumps({"error": "Both baseline and comparison IDs required"}),
                status=400,
                mimetype="application/json",
            )

        baseline = db_session.query(TestResult).get(baseline_id)
        comparison_result = db_session.query(TestResult).get(comparison_id)

        if not baseline:
            return Response(
                json.dumps({"error": f"Baseline #{baseline_id} not found"}),
                status=404,
                mimetype="application/json",
            )

        if not comparison_result:
            return Response(
                json.dumps({"error": f"Comparison #{comparison_id} not found"}),
                status=404,
                mimetype="application/json",
            )

        baseline_dict = _result_to_dict(baseline)
        comparison_dict = _result_to_dict(comparison_result)

        comparison = compare_test_results(baseline_dict, comparison_dict)

        return Response(
            json.dumps(comparison.to_dict(), default=str),
            mimetype="application/json",
        )
    finally:
        db_session.close()


def _result_to_dict(result: TestResult) -> dict[str, Any]:
    """Convert a TestResult model to a dictionary for comparison."""
    return {
        "id": result.id,
        "test_name": result.test_name,
        "test_type": result.test_type,
        "status": result.status,
        "started_at": result.started_at,
        "response_data": result.response_data,
        "request_data": result.request_data,
    }
