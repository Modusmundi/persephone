"""Test result comparison and diff tools.

Provides utilities for comparing test runs to detect changes in IdP behavior,
claim mappings, and validation results.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class DiffType(StrEnum):
    """Type of difference between two values."""

    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    UNCHANGED = "unchanged"


@dataclass
class ClaimDiff:
    """Represents a difference in a single claim."""

    claim_name: str
    diff_type: DiffType
    baseline_value: Any = None
    comparison_value: Any = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "claim_name": self.claim_name,
            "diff_type": str(self.diff_type),
            "baseline_value": self.baseline_value,
            "comparison_value": self.comparison_value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ClaimDiff:
        """Create from dictionary."""
        return cls(
            claim_name=data["claim_name"],
            diff_type=DiffType(data["diff_type"]),
            baseline_value=data.get("baseline_value"),
            comparison_value=data.get("comparison_value"),
        )


@dataclass
class ValidationDiff:
    """Represents a difference in a validation check."""

    check_name: str
    diff_type: DiffType
    baseline_status: str | None = None
    comparison_status: str | None = None
    baseline_message: str | None = None
    comparison_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "check_name": self.check_name,
            "diff_type": str(self.diff_type),
            "baseline_status": self.baseline_status,
            "comparison_status": self.comparison_status,
            "baseline_message": self.baseline_message,
            "comparison_message": self.comparison_message,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ValidationDiff:
        """Create from dictionary."""
        return cls(
            check_name=data["check_name"],
            diff_type=DiffType(data["diff_type"]),
            baseline_status=data.get("baseline_status"),
            comparison_status=data.get("comparison_status"),
            baseline_message=data.get("baseline_message"),
            comparison_message=data.get("comparison_message"),
        )


@dataclass
class TestComparison:
    """Complete comparison between two test results."""

    baseline_id: int
    comparison_id: int
    baseline_name: str
    comparison_name: str
    baseline_status: str
    comparison_status: str
    baseline_timestamp: str | None = None
    comparison_timestamp: str | None = None

    # Differences found
    status_changed: bool = False
    claim_diffs: list[ClaimDiff] = field(default_factory=list)
    validation_diffs: list[ValidationDiff] = field(default_factory=list)

    # Summary statistics
    claims_added: int = 0
    claims_removed: int = 0
    claims_modified: int = 0
    claims_unchanged: int = 0
    validations_added: int = 0
    validations_removed: int = 0
    validations_changed: int = 0
    validations_unchanged: int = 0

    # Regression indicators
    has_regressions: bool = False
    regression_details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "baseline_id": self.baseline_id,
            "comparison_id": self.comparison_id,
            "baseline_name": self.baseline_name,
            "comparison_name": self.comparison_name,
            "baseline_status": self.baseline_status,
            "comparison_status": self.comparison_status,
            "baseline_timestamp": self.baseline_timestamp,
            "comparison_timestamp": self.comparison_timestamp,
            "status_changed": self.status_changed,
            "claim_diffs": [d.to_dict() for d in self.claim_diffs],
            "validation_diffs": [d.to_dict() for d in self.validation_diffs],
            "claims_added": self.claims_added,
            "claims_removed": self.claims_removed,
            "claims_modified": self.claims_modified,
            "claims_unchanged": self.claims_unchanged,
            "validations_added": self.validations_added,
            "validations_removed": self.validations_removed,
            "validations_changed": self.validations_changed,
            "validations_unchanged": self.validations_unchanged,
            "has_regressions": self.has_regressions,
            "regression_details": self.regression_details,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TestComparison:
        """Create from dictionary."""
        comparison = cls(
            baseline_id=data["baseline_id"],
            comparison_id=data["comparison_id"],
            baseline_name=data["baseline_name"],
            comparison_name=data["comparison_name"],
            baseline_status=data["baseline_status"],
            comparison_status=data["comparison_status"],
            baseline_timestamp=data.get("baseline_timestamp"),
            comparison_timestamp=data.get("comparison_timestamp"),
            status_changed=data.get("status_changed", False),
            claims_added=data.get("claims_added", 0),
            claims_removed=data.get("claims_removed", 0),
            claims_modified=data.get("claims_modified", 0),
            claims_unchanged=data.get("claims_unchanged", 0),
            validations_added=data.get("validations_added", 0),
            validations_removed=data.get("validations_removed", 0),
            validations_changed=data.get("validations_changed", 0),
            validations_unchanged=data.get("validations_unchanged", 0),
            has_regressions=data.get("has_regressions", False),
            regression_details=data.get("regression_details", []),
        )
        comparison.claim_diffs = [
            ClaimDiff.from_dict(d) for d in data.get("claim_diffs", [])
        ]
        comparison.validation_diffs = [
            ValidationDiff.from_dict(d) for d in data.get("validation_diffs", [])
        ]
        return comparison


def compare_claims(
    baseline_claims: dict[str, Any] | None,
    comparison_claims: dict[str, Any] | None,
) -> list[ClaimDiff]:
    """Compare claims between two test results.

    Args:
        baseline_claims: Claims from the baseline test result
        comparison_claims: Claims from the comparison test result

    Returns:
        List of ClaimDiff objects describing differences
    """
    baseline_claims = baseline_claims or {}
    comparison_claims = comparison_claims or {}

    diffs: list[ClaimDiff] = []

    # Get all unique claim names
    all_claims = set(baseline_claims.keys()) | set(comparison_claims.keys())

    for claim_name in sorted(all_claims):
        baseline_value = baseline_claims.get(claim_name)
        comparison_value = comparison_claims.get(claim_name)

        if claim_name not in baseline_claims:
            # Claim was added in comparison
            diffs.append(ClaimDiff(
                claim_name=claim_name,
                diff_type=DiffType.ADDED,
                comparison_value=comparison_value,
            ))
        elif claim_name not in comparison_claims:
            # Claim was removed in comparison
            diffs.append(ClaimDiff(
                claim_name=claim_name,
                diff_type=DiffType.REMOVED,
                baseline_value=baseline_value,
            ))
        elif baseline_value != comparison_value:
            # Claim value changed
            diffs.append(ClaimDiff(
                claim_name=claim_name,
                diff_type=DiffType.MODIFIED,
                baseline_value=baseline_value,
                comparison_value=comparison_value,
            ))
        else:
            # Claim unchanged
            diffs.append(ClaimDiff(
                claim_name=claim_name,
                diff_type=DiffType.UNCHANGED,
                baseline_value=baseline_value,
                comparison_value=comparison_value,
            ))

    return diffs


def compare_validation_checks(
    baseline_validation: dict[str, Any] | None,
    comparison_validation: dict[str, Any] | None,
) -> list[ValidationDiff]:
    """Compare validation checks between two test results.

    Args:
        baseline_validation: Validation data from baseline test
        comparison_validation: Validation data from comparison test

    Returns:
        List of ValidationDiff objects describing differences
    """
    baseline_checks = (baseline_validation or {}).get("checks", [])
    comparison_checks = (comparison_validation or {}).get("checks", [])

    # Create lookup dictionaries by check name
    baseline_by_name = {check["name"]: check for check in baseline_checks}
    comparison_by_name = {check["name"]: check for check in comparison_checks}

    diffs: list[ValidationDiff] = []

    # Get all unique check names
    all_checks = set(baseline_by_name.keys()) | set(comparison_by_name.keys())

    for check_name in sorted(all_checks):
        baseline_check = baseline_by_name.get(check_name)
        comparison_check = comparison_by_name.get(check_name)

        if check_name not in baseline_by_name:
            # Check was added in comparison
            diffs.append(ValidationDiff(
                check_name=check_name,
                diff_type=DiffType.ADDED,
                comparison_status=comparison_check.get("status") if comparison_check else None,
                comparison_message=comparison_check.get("message") if comparison_check else None,
            ))
        elif check_name not in comparison_by_name:
            # Check was removed in comparison
            diffs.append(ValidationDiff(
                check_name=check_name,
                diff_type=DiffType.REMOVED,
                baseline_status=baseline_check.get("status") if baseline_check else None,
                baseline_message=baseline_check.get("message") if baseline_check else None,
            ))
        else:
            baseline_status = baseline_check.get("status") if baseline_check else None
            comparison_status = comparison_check.get("status") if comparison_check else None
            baseline_message = baseline_check.get("message") if baseline_check else None
            comparison_message = comparison_check.get("message") if comparison_check else None

            if baseline_status != comparison_status:
                # Status changed
                diffs.append(ValidationDiff(
                    check_name=check_name,
                    diff_type=DiffType.MODIFIED,
                    baseline_status=baseline_status,
                    comparison_status=comparison_status,
                    baseline_message=baseline_message,
                    comparison_message=comparison_message,
                ))
            else:
                # Status unchanged (message changes don't count as modifications)
                diffs.append(ValidationDiff(
                    check_name=check_name,
                    diff_type=DiffType.UNCHANGED,
                    baseline_status=baseline_status,
                    comparison_status=comparison_status,
                    baseline_message=baseline_message,
                    comparison_message=comparison_message,
                ))

    return diffs


def detect_regressions(
    comparison: TestComparison,
) -> tuple[bool, list[str]]:
    """Detect regressions in a comparison result.

    A regression is defined as:
    - Test status changed from passed to failed/error
    - Validation check changed from valid to invalid
    - Required claims were removed

    Args:
        comparison: The TestComparison to analyze

    Returns:
        Tuple of (has_regressions, list of regression descriptions)
    """
    regressions: list[str] = []

    # Check for status regression
    if comparison.baseline_status == "passed" and comparison.comparison_status in ("failed", "error"):
        regressions.append(
            f"Test status regressed from 'passed' to '{comparison.comparison_status}'"
        )

    # Check for validation regressions
    for val_diff in comparison.validation_diffs:
        if val_diff.diff_type == DiffType.MODIFIED and val_diff.baseline_status == "valid" and val_diff.comparison_status == "invalid":
            regressions.append(
                f"Validation '{val_diff.check_name}' regressed from 'valid' to 'invalid'"
            )

    # Check for removed critical claims
    critical_claims = {"sub", "iss", "aud", "exp", "iat", "email", "name"}
    for claim_diff in comparison.claim_diffs:
        if claim_diff.diff_type == DiffType.REMOVED and claim_diff.claim_name in critical_claims:
            regressions.append(
                f"Critical claim '{claim_diff.claim_name}' was removed"
            )

    return len(regressions) > 0, regressions


def compare_test_results(
    baseline: dict[str, Any],
    comparison: dict[str, Any],
) -> TestComparison:
    """Compare two test results and generate a full comparison report.

    Args:
        baseline: The baseline test result dictionary
        comparison: The comparison test result dictionary

    Returns:
        TestComparison object with all differences
    """
    # Extract claims from response data
    baseline_claims = (baseline.get("response_data") or {}).get("claims")
    comparison_claims = (comparison.get("response_data") or {}).get("claims")

    # Extract validation from response data
    baseline_validation = (baseline.get("response_data") or {}).get("validation")
    comparison_validation = (comparison.get("response_data") or {}).get("validation")

    # Get timestamps
    baseline_timestamp = baseline.get("started_at")
    if baseline_timestamp and not isinstance(baseline_timestamp, str):
        baseline_timestamp = baseline_timestamp.isoformat() if hasattr(baseline_timestamp, 'isoformat') else str(baseline_timestamp)

    comparison_timestamp = comparison.get("started_at")
    if comparison_timestamp and not isinstance(comparison_timestamp, str):
        comparison_timestamp = comparison_timestamp.isoformat() if hasattr(comparison_timestamp, 'isoformat') else str(comparison_timestamp)

    # Create comparison object
    result = TestComparison(
        baseline_id=baseline.get("id", 0),
        comparison_id=comparison.get("id", 0),
        baseline_name=baseline.get("test_name", "Unknown"),
        comparison_name=comparison.get("test_name", "Unknown"),
        baseline_status=baseline.get("status", "unknown"),
        comparison_status=comparison.get("status", "unknown"),
        baseline_timestamp=baseline_timestamp,
        comparison_timestamp=comparison_timestamp,
    )

    # Check for status change
    result.status_changed = result.baseline_status != result.comparison_status

    # Compare claims
    result.claim_diffs = compare_claims(baseline_claims, comparison_claims)

    # Calculate claim statistics
    for claim_diff in result.claim_diffs:
        if claim_diff.diff_type == DiffType.ADDED:
            result.claims_added += 1
        elif claim_diff.diff_type == DiffType.REMOVED:
            result.claims_removed += 1
        elif claim_diff.diff_type == DiffType.MODIFIED:
            result.claims_modified += 1
        else:
            result.claims_unchanged += 1

    # Compare validation checks
    result.validation_diffs = compare_validation_checks(
        baseline_validation, comparison_validation
    )

    # Calculate validation statistics
    for val_diff in result.validation_diffs:
        if val_diff.diff_type == DiffType.ADDED:
            result.validations_added += 1
        elif val_diff.diff_type == DiffType.REMOVED:
            result.validations_removed += 1
        elif val_diff.diff_type == DiffType.MODIFIED:
            result.validations_changed += 1
        else:
            result.validations_unchanged += 1

    # Detect regressions
    result.has_regressions, result.regression_details = detect_regressions(result)

    return result


def compare_with_baseline(
    baseline: dict[str, Any],
    test_results: list[dict[str, Any]],
) -> list[TestComparison]:
    """Compare multiple test results against a single baseline.

    Useful for baseline comparison mode where one test is the reference
    point for all others.

    Args:
        baseline: The baseline test result dictionary
        test_results: List of test results to compare against baseline

    Returns:
        List of TestComparison objects
    """
    comparisons = []
    for test in test_results:
        if test.get("id") != baseline.get("id"):
            comparisons.append(compare_test_results(baseline, test))
    return comparisons
