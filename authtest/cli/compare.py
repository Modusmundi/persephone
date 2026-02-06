"""Test comparison CLI commands."""

from __future__ import annotations

import json
import sys
from typing import Any, NoReturn

import click

# Common option for JSON output
json_option = click.option(
    "--json",
    "output_json",
    is_flag=True,
    help="Output results as JSON for scripting",
)


def output_result(data: dict[str, Any], as_json: bool = False) -> None:
    """Output result as JSON or formatted text."""
    if as_json:
        click.echo(json.dumps(data, indent=2, default=str))


def error_result(message: str, as_json: bool = False) -> NoReturn:
    """Output error message and exit."""
    if as_json:
        click.echo(json.dumps({"error": message}, indent=2), err=True)
        sys.exit(1)
    raise click.ClickException(message)


@click.group()
def compare() -> None:
    """Compare test results to detect changes.

    Compare test runs to identify changes in IdP behavior, claim mappings,
    and validation results. Useful for regression detection and baseline
    comparison.
    """
    pass


@compare.command("diff")
@click.argument("baseline_id", type=int)
@click.argument("comparison_id", type=int)
@click.option(
    "--show-unchanged",
    is_flag=True,
    help="Include unchanged claims and validations in output",
)
@json_option
def compare_diff(
    baseline_id: int,
    comparison_id: int,
    show_unchanged: bool,
    output_json: bool,
) -> None:
    """Compare two test results side-by-side.

    Shows differences in claims, validation checks, and test status between
    the baseline and comparison test results.

    BASELINE_ID is the reference test result ID.
    COMPARISON_ID is the test result to compare against baseline.

    Examples:

        # Compare two tests
        authtest compare diff 42 43

        # Show all differences including unchanged
        authtest compare diff 42 43 --show-unchanged

        # Output as JSON
        authtest compare diff 42 43 --json
    """
    from authtest.reports import DiffType, compare_test_results
    from authtest.storage import Database, KeyNotFoundError, TestResult

    try:
        database = Database()
        session = database.get_session()

        # Load both test results
        baseline = session.query(TestResult).get(baseline_id)
        if not baseline:
            session.close()
            database.close()
            error_result(f"Baseline test result with ID {baseline_id} not found.", output_json)

        comparison_result = session.query(TestResult).get(comparison_id)
        if not comparison_result:
            session.close()
            database.close()
            error_result(f"Comparison test result with ID {comparison_id} not found.", output_json)

        # Convert to dictionaries for comparison
        baseline_dict = {
            "id": baseline.id,
            "test_name": baseline.test_name,
            "test_type": baseline.test_type,
            "status": baseline.status,
            "started_at": baseline.started_at,
            "response_data": baseline.response_data,
        }

        comparison_dict = {
            "id": comparison_result.id,
            "test_name": comparison_result.test_name,
            "test_type": comparison_result.test_type,
            "status": comparison_result.status,
            "started_at": comparison_result.started_at,
            "response_data": comparison_result.response_data,
        }

        session.close()
        database.close()

        # Perform comparison
        result = compare_test_results(baseline_dict, comparison_dict)

        if output_json:
            output_result(result.to_dict(), as_json=True)
        else:
            # Display comparison
            click.echo("=" * 60)
            click.echo("TEST COMPARISON")
            click.echo("=" * 60)
            click.echo("")

            # Header
            click.echo(f"Baseline:   #{result.baseline_id} - {result.baseline_name}")
            click.echo(f"            Status: {result.baseline_status} | {result.baseline_timestamp or 'N/A'}")
            click.echo(f"Comparison: #{result.comparison_id} - {result.comparison_name}")
            click.echo(f"            Status: {result.comparison_status} | {result.comparison_timestamp or 'N/A'}")
            click.echo("")

            # Status change
            if result.status_changed:
                click.echo(click.style(
                    f"STATUS CHANGED: {result.baseline_status} -> {result.comparison_status}",
                    fg="yellow", bold=True
                ))
                click.echo("")

            # Regressions
            if result.has_regressions:
                click.echo(click.style("REGRESSIONS DETECTED:", fg="red", bold=True))
                for detail in result.regression_details:
                    click.echo(click.style(f"  - {detail}", fg="red"))
                click.echo("")

            # Claims summary
            click.echo("CLAIMS COMPARISON:")
            click.echo(f"  Added: {result.claims_added} | Removed: {result.claims_removed} | "
                      f"Modified: {result.claims_modified} | Unchanged: {result.claims_unchanged}")
            click.echo("")

            # Claim details
            if result.claim_diffs:
                for diff in result.claim_diffs:
                    if diff.diff_type == DiffType.UNCHANGED and not show_unchanged:
                        continue

                    if diff.diff_type == DiffType.ADDED:
                        click.echo(click.style(f"  + {diff.claim_name}: {diff.comparison_value}", fg="green"))
                    elif diff.diff_type == DiffType.REMOVED:
                        click.echo(click.style(f"  - {diff.claim_name}: {diff.baseline_value}", fg="red"))
                    elif diff.diff_type == DiffType.MODIFIED:
                        click.echo(click.style(f"  ~ {diff.claim_name}:", fg="yellow"))
                        click.echo(f"      baseline:   {diff.baseline_value}")
                        click.echo(f"      comparison: {diff.comparison_value}")
                    else:
                        click.echo(f"    {diff.claim_name}: {diff.baseline_value}")
                click.echo("")

            # Validation summary
            click.echo("VALIDATION COMPARISON:")
            click.echo(f"  Added: {result.validations_added} | Removed: {result.validations_removed} | "
                      f"Changed: {result.validations_changed} | Unchanged: {result.validations_unchanged}")
            click.echo("")

            # Validation details
            if result.validation_diffs:
                for val_diff in result.validation_diffs:
                    if val_diff.diff_type == DiffType.UNCHANGED and not show_unchanged:
                        continue

                    if val_diff.diff_type == DiffType.ADDED:
                        click.echo(click.style(f"  + {val_diff.check_name}: {val_diff.comparison_status}", fg="green"))
                    elif val_diff.diff_type == DiffType.REMOVED:
                        click.echo(click.style(f"  - {val_diff.check_name}: {val_diff.baseline_status}", fg="red"))
                    elif val_diff.diff_type == DiffType.MODIFIED:
                        click.echo(click.style(f"  ~ {val_diff.check_name}: {val_diff.baseline_status} -> {val_diff.comparison_status}", fg="yellow"))
                    else:
                        click.echo(f"    {val_diff.check_name}: {val_diff.baseline_status}")

    except KeyNotFoundError as e:
        error_result(f"Database not initialized: {e}\nRun 'authtest config init' first.", output_json)


@compare.command("baseline")
@click.argument("baseline_id", type=int)
@click.option(
    "--idp",
    "idp_name",
    help="Compare only tests from this IdP",
)
@click.option(
    "--type",
    "test_type",
    type=click.Choice(["saml", "oidc"]),
    help="Compare only tests of this type",
)
@click.option(
    "--limit",
    default=10,
    type=int,
    help="Maximum number of comparisons (default: 10)",
)
@click.option(
    "--regressions-only",
    is_flag=True,
    help="Show only comparisons with regressions",
)
@json_option
def compare_baseline(
    baseline_id: int,
    idp_name: str | None,
    test_type: str | None,
    limit: int,
    regressions_only: bool,
    output_json: bool,
) -> None:
    """Compare multiple tests against a baseline.

    Compares recent test results against a specified baseline test to detect
    regressions and changes across multiple test runs.

    BASELINE_ID is the reference test result to compare against.

    Examples:

        # Compare recent tests against baseline
        authtest compare baseline 42

        # Compare only OIDC tests
        authtest compare baseline 42 --type oidc

        # Show only regressions
        authtest compare baseline 42 --regressions-only

        # Limit to 5 comparisons
        authtest compare baseline 42 --limit 5
    """
    from authtest.reports import compare_with_baseline
    from authtest.storage import Database, IdPProvider, KeyNotFoundError, TestResult

    try:
        database = Database()
        session = database.get_session()

        # Load baseline
        baseline = session.query(TestResult).get(baseline_id)
        if not baseline:
            session.close()
            database.close()
            error_result(f"Baseline test result with ID {baseline_id} not found.", output_json)

        baseline_dict = {
            "id": baseline.id,
            "test_name": baseline.test_name,
            "test_type": baseline.test_type,
            "status": baseline.status,
            "started_at": baseline.started_at,
            "response_data": baseline.response_data,
        }

        # Build query for comparison tests
        query = session.query(TestResult).filter(TestResult.id != baseline_id)

        if idp_name:
            query = query.join(IdPProvider).filter(IdPProvider.name == idp_name)
        elif baseline.idp_provider_id:
            # Default to same IdP as baseline
            query = query.filter(TestResult.idp_provider_id == baseline.idp_provider_id)

        if test_type:
            query = query.filter(TestResult.test_type == test_type)
        else:
            # Default to same type as baseline
            query = query.filter(TestResult.test_type == baseline.test_type)

        # Get recent results
        results = (
            query.order_by(TestResult.started_at.desc())
            .limit(limit)
            .all()
        )

        if not results:
            session.close()
            database.close()
            if output_json:
                output_result({"comparisons": [], "message": "No test results found for comparison."}, as_json=True)
            else:
                click.echo("No test results found for comparison.")
            return

        # Convert to dictionaries
        comparison_dicts = [
            {
                "id": r.id,
                "test_name": r.test_name,
                "test_type": r.test_type,
                "status": r.status,
                "started_at": r.started_at,
                "response_data": r.response_data,
            }
            for r in results
        ]

        session.close()
        database.close()

        # Perform comparisons
        comparisons = compare_with_baseline(baseline_dict, comparison_dicts)

        # Filter by regressions if requested
        if regressions_only:
            comparisons = [c for c in comparisons if c.has_regressions]

        if output_json:
            output_result({
                "baseline_id": baseline_id,
                "comparisons": [c.to_dict() for c in comparisons],
                "total": len(comparisons),
                "with_regressions": sum(1 for c in comparisons if c.has_regressions),
            }, as_json=True)
        else:
            click.echo("=" * 60)
            click.echo(f"BASELINE COMPARISON (ID: {baseline_id})")
            click.echo("=" * 60)
            click.echo(f"Baseline: {baseline_dict['test_name']} ({baseline_dict['status']})")
            click.echo(f"Comparing against {len(comparisons)} test result(s)")
            click.echo("")

            regression_count = sum(1 for c in comparisons if c.has_regressions)
            if regression_count > 0:
                click.echo(click.style(f"REGRESSIONS FOUND: {regression_count}", fg="red", bold=True))
                click.echo("")

            for comp in comparisons:
                status_color = "green" if not comp.has_regressions else "red"
                status_icon = "OK" if not comp.has_regressions else "REGRESSION"

                click.echo(f"  #{comp.comparison_id} - {comp.comparison_name}")
                click.echo(f"     Status: {comp.comparison_status} | " +
                          click.style(status_icon, fg=status_color))
                click.echo(f"     Claims: +{comp.claims_added} -{comp.claims_removed} ~{comp.claims_modified}")
                click.echo(f"     Validation: +{comp.validations_added} -{comp.validations_removed} ~{comp.validations_changed}")

                if comp.has_regressions:
                    for detail in comp.regression_details:
                        click.echo(click.style(f"       ! {detail}", fg="red"))
                click.echo("")

    except KeyNotFoundError as e:
        error_result(f"Database not initialized: {e}\nRun 'authtest config init' first.", output_json)


@compare.command("regressions")
@click.option(
    "--idp",
    "idp_name",
    help="Filter by IdP name",
)
@click.option(
    "--type",
    "test_type",
    type=click.Choice(["saml", "oidc"]),
    help="Filter by protocol type",
)
@click.option(
    "--limit",
    default=20,
    type=int,
    help="Maximum number of test pairs to compare (default: 20)",
)
@json_option
def detect_regressions_cmd(
    idp_name: str | None,
    test_type: str | None,
    limit: int,
    output_json: bool,
) -> None:
    """Detect regressions by comparing consecutive test runs.

    Compares each test with the previous test of the same name to detect
    regressions in test status, validation, or claims.

    Examples:

        # Find all regressions
        authtest compare regressions

        # Find regressions for OIDC tests
        authtest compare regressions --type oidc

        # Find regressions for specific IdP
        authtest compare regressions --idp my-okta
    """
    from authtest.reports import compare_test_results
    from authtest.storage import Database, IdPProvider, KeyNotFoundError, TestResult

    try:
        database = Database()
        session = database.get_session()

        # Build query
        query = session.query(TestResult)

        if idp_name:
            query = query.join(IdPProvider).filter(IdPProvider.name == idp_name)

        if test_type:
            query = query.filter(TestResult.test_type == test_type)

        # Get results ordered by test name and date
        results = (
            query.order_by(TestResult.test_name, TestResult.started_at.desc())
            .limit(limit * 2)  # Get more to ensure we have pairs
            .all()
        )

        if len(results) < 2:
            session.close()
            database.close()
            if output_json:
                output_result({"regressions": [], "message": "Not enough test results for regression detection."}, as_json=True)
            else:
                click.echo("Not enough test results for regression detection.")
            return

        # Group by test name to find consecutive runs
        test_groups: dict[str, list[Any]] = {}
        for r in results:
            if r.test_name not in test_groups:
                test_groups[r.test_name] = []
            test_groups[r.test_name].append(r)

        regressions_found = []
        comparison_count = 0

        for _test_name, group_results in test_groups.items():
            if len(group_results) < 2 or comparison_count >= limit:
                continue

            # Compare most recent with previous
            newer = group_results[0]
            older = group_results[1]

            older_dict = {
                "id": older.id,
                "test_name": older.test_name,
                "test_type": older.test_type,
                "status": older.status,
                "started_at": older.started_at,
                "response_data": older.response_data,
            }

            newer_dict = {
                "id": newer.id,
                "test_name": newer.test_name,
                "test_type": newer.test_type,
                "status": newer.status,
                "started_at": newer.started_at,
                "response_data": newer.response_data,
            }

            comparison = compare_test_results(older_dict, newer_dict)
            comparison_count += 1

            if comparison.has_regressions:
                regressions_found.append(comparison)

        session.close()
        database.close()

        if output_json:
            output_result({
                "comparisons_checked": comparison_count,
                "regressions_found": len(regressions_found),
                "regressions": [r.to_dict() for r in regressions_found],
            }, as_json=True)
        else:
            click.echo("=" * 60)
            click.echo("REGRESSION DETECTION")
            click.echo("=" * 60)
            click.echo(f"Compared {comparison_count} test pairs")
            click.echo("")

            if not regressions_found:
                click.echo(click.style("No regressions detected!", fg="green", bold=True))
            else:
                click.echo(click.style(f"REGRESSIONS FOUND: {len(regressions_found)}", fg="red", bold=True))
                click.echo("")

                for comp in regressions_found:
                    click.echo(f"  {comp.baseline_name}")
                    click.echo(f"    #{comp.baseline_id} ({comp.baseline_status}) -> "
                              f"#{comp.comparison_id} ({comp.comparison_status})")
                    for detail in comp.regression_details:
                        click.echo(click.style(f"      ! {detail}", fg="red"))
                    click.echo("")

    except KeyNotFoundError as e:
        error_result(f"Database not initialized: {e}\nRun 'authtest config init' first.", output_json)
