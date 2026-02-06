"""Test history management CLI commands."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
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
def history() -> None:
    """Manage test execution history.

    Browse, search, export, and delete test results from your authentication
    flow testing sessions.
    """
    pass


@history.command("list")
@click.option("--idp", "idp_name", help="Filter by IdP name")
@click.option(
    "--type",
    "test_type",
    type=click.Choice(["saml", "oidc"]),
    help="Filter by protocol type",
)
@click.option(
    "--status",
    "test_status",
    type=click.Choice(["passed", "failed", "error"]),
    help="Filter by test status",
)
@click.option(
    "--since",
    help="Filter tests since date (YYYY-MM-DD) or duration (e.g., '7d', '24h')",
)
@click.option(
    "--until",
    help="Filter tests until date (YYYY-MM-DD)",
)
@click.option(
    "--limit",
    default=50,
    type=int,
    help="Maximum number of results (default: 50)",
)
@click.option(
    "--offset",
    default=0,
    type=int,
    help="Number of results to skip (for pagination)",
)
@json_option
def history_list(
    idp_name: str | None,
    test_type: str | None,
    test_status: str | None,
    since: str | None,
    until: str | None,
    limit: int,
    offset: int,
    output_json: bool,
) -> None:
    """List test execution history.

    Shows recent test results with optional filtering by IdP, protocol type,
    status, and date range.

    Examples:

        # List all recent tests
        authtest history list

        # Filter by IdP
        authtest history list --idp my-okta

        # Filter by status and type
        authtest history list --status failed --type oidc

        # Tests from the last 7 days
        authtest history list --since 7d

        # Tests in a date range
        authtest history list --since 2024-01-01 --until 2024-01-31

        # Pagination
        authtest history list --limit 20 --offset 40
    """
    from authtest.storage import Database, IdPProvider, KeyNotFoundError, TestResult

    # Parse date filters
    since_dt: datetime | None = None
    until_dt: datetime | None = None

    if since:
        since_dt = _parse_date_or_duration(since)
        if not since_dt:
            error_result(f"Invalid date format: {since}. Use YYYY-MM-DD or duration like '7d', '24h'.", output_json)

    if until:
        until_dt = _parse_date_or_duration(until, end_of_day=True)
        if not until_dt:
            error_result(f"Invalid date format: {until}. Use YYYY-MM-DD.", output_json)

    try:
        database = Database()
        session = database.get_session()

        # Build query
        query = session.query(TestResult)

        # Join with IdP if filtering by name
        if idp_name:
            query = query.join(IdPProvider).filter(IdPProvider.name == idp_name)

        # Apply filters
        if test_type:
            query = query.filter(TestResult.test_type == test_type)

        if test_status:
            query = query.filter(TestResult.status == test_status)

        if since_dt:
            query = query.filter(TestResult.started_at >= since_dt)

        if until_dt:
            query = query.filter(TestResult.started_at <= until_dt)

        # Get total count before pagination
        total_count = query.count()

        # Order by most recent first and apply pagination
        results = (
            query.order_by(TestResult.started_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        # Format results
        result_data = []
        for result in results:
            idp_display = result.idp_provider.name if result.idp_provider else "(unknown)"
            result_data.append({
                "id": result.id,
                "test_name": result.test_name,
                "test_type": result.test_type,
                "idp": idp_display,
                "status": result.status,
                "started_at": result.started_at,
                "duration_ms": result.duration_ms,
                "error": result.error_message,
            })

        session.close()
        database.close()

        output = {
            "total": total_count,
            "offset": offset,
            "limit": limit,
            "count": len(result_data),
            "results": result_data,
        }

        if output_json:
            output_result(output, as_json=True)
        else:
            if not result_data:
                click.echo("No test results found matching the criteria.")
                return

            click.echo(f"Test Results ({len(result_data)} of {total_count}):")
            click.echo("")
            for r in result_data:
                status_color = {
                    "passed": "green",
                    "failed": "red",
                    "error": "yellow",
                }.get(r["status"], "white")
                status = click.style(r["status"], fg=status_color)

                duration = f"{r['duration_ms']}ms" if r["duration_ms"] else "N/A"
                timestamp = r["started_at"].strftime("%Y-%m-%d %H:%M") if r["started_at"] else "N/A"

                click.echo(f"  [{r['id']:4d}] {r['test_name'][:40]:<40} {status:<8}")
                click.echo(f"         {r['test_type'].upper():<5} | {r['idp']:<20} | {timestamp} | {duration}")
                if r["error"]:
                    click.echo(f"         Error: {r['error'][:60]}...")
                click.echo("")

            if total_count > offset + limit:
                click.echo(f"Use --offset {offset + limit} to see more results.")

    except KeyNotFoundError as e:
        error_result(f"Database not initialized: {e}\nRun 'authtest config init' first.", output_json)


@history.command("show")
@click.argument("test_id", type=int)
@json_option
def history_show(test_id: int, output_json: bool) -> None:
    """Show detailed information about a specific test result.

    TEST_ID is the numeric identifier shown in 'history list' output.

    Examples:

        # Show test details
        authtest history show 42

        # Show as JSON
        authtest history show 42 --json
    """
    from authtest.storage import Database, KeyNotFoundError, TestResult

    try:
        database = Database()
        session = database.get_session()

        result = session.query(TestResult).get(test_id)
        if not result:
            session.close()
            database.close()
            error_result(f"Test result with ID {test_id} not found.", output_json)

        idp_name = result.idp_provider.name if result.idp_provider else None
        idp_display_name = result.idp_provider.display_name if result.idp_provider else None

        result_data: dict[str, Any] = {
            "id": result.id,
            "test_name": result.test_name,
            "test_type": result.test_type,
            "status": result.status,
            "idp": {
                "id": result.idp_provider_id,
                "name": idp_name,
                "display_name": idp_display_name,
            },
            "timing": {
                "started_at": result.started_at,
                "completed_at": result.completed_at,
                "duration_ms": result.duration_ms,
            },
            "error": {
                "message": result.error_message,
                "details": result.error_details,
            } if result.error_message else None,
            "request_data": result.request_data,
            "response_data": result.response_data,
        }

        session.close()
        database.close()

        if output_json:
            output_result(result_data, as_json=True)
        else:
            status_color = {
                "passed": "green",
                "failed": "red",
                "error": "yellow",
            }.get(result_data["status"], "white")
            status = click.style(result_data["status"].upper(), fg=status_color, bold=True)

            click.echo(f"Test Result #{result_data['id']}")
            click.echo("=" * 50)
            click.echo(f"Name: {result_data['test_name']}")
            click.echo(f"Type: {result_data['test_type'].upper()}")
            click.echo(f"Status: {status}")
            click.echo(f"IdP: {result_data['idp']['display_name'] or result_data['idp']['name'] or '(unknown)'}")
            click.echo("")

            click.echo("Timing:")
            timing = result_data["timing"]
            click.echo(f"  Started: {timing['started_at']}")
            click.echo(f"  Completed: {timing['completed_at'] or 'N/A'}")
            click.echo(f"  Duration: {timing['duration_ms']}ms" if timing["duration_ms"] else "  Duration: N/A")

            if result_data["error"]:
                click.echo("")
                click.echo(click.style("Error:", fg="red"))
                click.echo(f"  {result_data['error']['message']}")
                if result_data["error"]["details"]:
                    click.echo(f"  Details: {json.dumps(result_data['error']['details'], indent=4)}")

            if result_data["request_data"]:
                click.echo("")
                click.echo("Request Data:")
                click.echo(f"  {json.dumps(result_data['request_data'], indent=2, default=str)[:500]}...")

            if result_data["response_data"]:
                click.echo("")
                click.echo("Response Data:")
                # Show a summary, not the full data
                resp = result_data["response_data"]
                if "tokens" in resp:
                    click.echo("  Tokens received: Yes")
                if "validation" in resp:
                    click.echo(f"  Validation checks: {len(resp.get('validation', {}).get('checks', []))}")
                if "claims" in resp:
                    claims = resp["claims"]
                    click.echo(f"  Claims: {len(claims)} total")
                    for key in ["sub", "email", "name"]:
                        if key in claims:
                            click.echo(f"    {key}: {claims[key]}")

    except KeyNotFoundError as e:
        error_result(f"Database not initialized: {e}\nRun 'authtest config init' first.", output_json)


@history.command("export")
@click.argument("output_path", type=click.Path(path_type=Path))
@click.option("--idp", "idp_name", help="Filter by IdP name")
@click.option(
    "--type",
    "test_type",
    type=click.Choice(["saml", "oidc"]),
    help="Filter by protocol type",
)
@click.option(
    "--status",
    "test_status",
    type=click.Choice(["passed", "failed", "error"]),
    help="Filter by test status",
)
@click.option(
    "--since",
    help="Filter tests since date (YYYY-MM-DD) or duration (e.g., '7d', '24h')",
)
@click.option(
    "--until",
    help="Filter tests until date (YYYY-MM-DD)",
)
@click.option(
    "--ids",
    help="Comma-separated list of specific test IDs to export",
)
@click.option(
    "--format",
    "export_format",
    type=click.Choice(["json", "csv"]),
    default="json",
    help="Export format (default: json)",
)
@json_option
def history_export(
    output_path: Path,
    idp_name: str | None,
    test_type: str | None,
    test_status: str | None,
    since: str | None,
    until: str | None,
    ids: str | None,
    export_format: str,
    output_json: bool,
) -> None:
    """Export test results to a file.

    Exports test results matching the specified filters to JSON or CSV format.

    Examples:

        # Export all results
        authtest history export results.json

        # Export failed tests only
        authtest history export failed.json --status failed

        # Export specific tests by ID
        authtest history export selected.json --ids 1,2,3,4

        # Export as CSV
        authtest history export results.csv --format csv

        # Export with filters
        authtest history export report.json --idp my-okta --since 7d
    """
    from authtest.storage import Database, IdPProvider, KeyNotFoundError, TestResult

    # Parse date filters
    since_dt: datetime | None = None
    until_dt: datetime | None = None

    if since:
        since_dt = _parse_date_or_duration(since)
        if not since_dt:
            error_result(f"Invalid date format: {since}. Use YYYY-MM-DD or duration like '7d', '24h'.", output_json)

    if until:
        until_dt = _parse_date_or_duration(until, end_of_day=True)
        if not until_dt:
            error_result(f"Invalid date format: {until}. Use YYYY-MM-DD.", output_json)

    # Parse IDs if provided
    id_list: list[int] | None = None
    if ids:
        try:
            id_list = [int(x.strip()) for x in ids.split(",")]
        except ValueError:
            error_result("Invalid ID list. Use comma-separated integers.", output_json)

    try:
        database = Database()
        session = database.get_session()

        # Build query
        query = session.query(TestResult)

        # Filter by specific IDs if provided
        if id_list:
            query = query.filter(TestResult.id.in_(id_list))
        else:
            # Join with IdP if filtering by name
            if idp_name:
                query = query.join(IdPProvider).filter(IdPProvider.name == idp_name)

            # Apply other filters
            if test_type:
                query = query.filter(TestResult.test_type == test_type)

            if test_status:
                query = query.filter(TestResult.status == test_status)

            if since_dt:
                query = query.filter(TestResult.started_at >= since_dt)

            if until_dt:
                query = query.filter(TestResult.started_at <= until_dt)

        # Order by date
        results = query.order_by(TestResult.started_at.desc()).all()

        if not results:
            session.close()
            database.close()
            error_result("No test results found matching the criteria.", output_json)

        # Format results
        export_data = []
        for result in results:
            idp_display = result.idp_provider.name if result.idp_provider else None
            export_data.append({
                "id": result.id,
                "test_name": result.test_name,
                "test_type": result.test_type,
                "idp_name": idp_display,
                "status": result.status,
                "started_at": result.started_at.isoformat() if result.started_at else None,
                "completed_at": result.completed_at.isoformat() if result.completed_at else None,
                "duration_ms": result.duration_ms,
                "error_message": result.error_message,
                "error_details": result.error_details,
                "request_data": result.request_data,
                "response_data": result.response_data,
            })

        session.close()
        database.close()

        # Write to file
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if export_format == "json":
            output_path.write_text(json.dumps({
                "exported_at": datetime.now(UTC).isoformat(),
                "count": len(export_data),
                "results": export_data,
            }, indent=2, default=str))
        else:  # csv
            import csv
            with output_path.open("w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=[
                    "id", "test_name", "test_type", "idp_name", "status",
                    "started_at", "completed_at", "duration_ms", "error_message",
                ])
                writer.writeheader()
                for row in export_data:
                    # Exclude complex JSON fields for CSV
                    csv_row = {k: v for k, v in row.items() if k not in ["error_details", "request_data", "response_data"]}
                    writer.writerow(csv_row)

        result = {
            "status": "exported",
            "file": str(output_path),
            "format": export_format,
            "count": len(export_data),
        }

        if output_json:
            output_result(result, as_json=True)
        else:
            click.echo(f"Exported {len(export_data)} test result(s) to: {output_path}")
            click.echo(f"Format: {export_format.upper()}")

    except KeyNotFoundError as e:
        error_result(f"Database not initialized: {e}\nRun 'authtest config init' first.", output_json)


@history.command("delete")
@click.option("--idp", "idp_name", help="Delete results for specific IdP")
@click.option(
    "--type",
    "test_type",
    type=click.Choice(["saml", "oidc"]),
    help="Delete results for specific protocol type",
)
@click.option(
    "--status",
    "test_status",
    type=click.Choice(["passed", "failed", "error"]),
    help="Delete results with specific status",
)
@click.option(
    "--before",
    help="Delete results before date (YYYY-MM-DD) or duration (e.g., '30d')",
)
@click.option(
    "--ids",
    help="Comma-separated list of specific test IDs to delete",
)
@click.option(
    "--all",
    "delete_all",
    is_flag=True,
    help="Delete all test results (use with caution)",
)
@click.option(
    "--force",
    "-f",
    is_flag=True,
    help="Skip confirmation prompt",
)
@json_option
def history_delete(
    idp_name: str | None,
    test_type: str | None,
    test_status: str | None,
    before: str | None,
    ids: str | None,
    delete_all: bool,
    force: bool,
    output_json: bool,
) -> None:
    """Delete test results from history.

    Removes test results matching the specified criteria. This operation
    cannot be undone - consider exporting first.

    Examples:

        # Delete specific tests by ID
        authtest history delete --ids 1,2,3

        # Delete all failed tests
        authtest history delete --status failed

        # Delete tests older than 30 days
        authtest history delete --before 30d

        # Delete all results for an IdP
        authtest history delete --idp old-idp --force

        # Delete all history (dangerous)
        authtest history delete --all --force
    """
    from authtest.storage import Database, IdPProvider, KeyNotFoundError, TestResult

    # Validate that at least one filter is provided
    if not any([idp_name, test_type, test_status, before, ids, delete_all]):
        error_result(
            "Please specify at least one filter (--idp, --type, --status, --before, --ids) or use --all.",
            output_json,
        )

    # Parse date filter
    before_dt: datetime | None = None
    if before:
        before_dt = _parse_date_or_duration(before, end_of_day=True)
        if not before_dt:
            error_result(f"Invalid date format: {before}. Use YYYY-MM-DD or duration like '30d'.", output_json)

    # Parse IDs if provided
    id_list: list[int] | None = None
    if ids:
        try:
            id_list = [int(x.strip()) for x in ids.split(",")]
        except ValueError:
            error_result("Invalid ID list. Use comma-separated integers.", output_json)

    try:
        database = Database()
        session = database.get_session()

        # Build query
        query = session.query(TestResult)

        # Filter by specific IDs if provided
        if id_list:
            query = query.filter(TestResult.id.in_(id_list))
        elif not delete_all:
            # Join with IdP if filtering by name
            if idp_name:
                query = query.join(IdPProvider).filter(IdPProvider.name == idp_name)

            # Apply other filters
            if test_type:
                query = query.filter(TestResult.test_type == test_type)

            if test_status:
                query = query.filter(TestResult.status == test_status)

            if before_dt:
                query = query.filter(TestResult.started_at <= before_dt)

        # Count matching results
        count = query.count()

        if count == 0:
            session.close()
            database.close()
            if output_json:
                output_result({"status": "no_matches", "deleted": 0}, as_json=True)
            else:
                click.echo("No test results found matching the criteria.")
            return

        # Confirm deletion
        if not force and not output_json:
            click.confirm(
                f"This will delete {count} test result(s). This action cannot be undone. Continue?",
                abort=True,
            )

        # Perform deletion
        deleted = query.delete(synchronize_session="fetch")
        session.commit()

        session.close()
        database.close()

        result = {
            "status": "deleted",
            "count": deleted,
        }

        if output_json:
            output_result(result, as_json=True)
        else:
            click.echo(f"Deleted {deleted} test result(s).")

    except KeyNotFoundError as e:
        error_result(f"Database not initialized: {e}\nRun 'authtest config init' first.", output_json)


def _parse_date_or_duration(value: str, end_of_day: bool = False) -> datetime | None:
    """Parse a date string or duration.

    Args:
        value: Either a date (YYYY-MM-DD) or duration (e.g., '7d', '24h')
        end_of_day: If True and parsing a date, return end of day instead of start

    Returns:
        datetime object or None if parsing fails
    """
    # Try duration format first (e.g., '7d', '24h', '30m')
    if value and value[-1] in "dhm":
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
