"""Tests for the CLI commands."""

from click.testing import CliRunner

from authtest.cli.main import cli


def test_cli_version() -> None:
    """Test CLI version command."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_cli_help() -> None:
    """Test CLI help command."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "SAML/OIDC Authentication Flow Testing Tool" in result.output


def test_cli_init() -> None:
    """Test CLI init command."""
    runner = CliRunner()
    result = runner.invoke(cli, ["init"])
    assert result.exit_code == 0
    assert "Initializing AuthTest" in result.output


def test_config_idp_list() -> None:
    """Test config idp list command."""
    runner = CliRunner()
    result = runner.invoke(cli, ["config", "idp", "list"])
    assert result.exit_code == 0


def test_certs_list() -> None:
    """Test certs list command."""
    runner = CliRunner()
    result = runner.invoke(cli, ["certs", "list"])
    assert result.exit_code == 0
