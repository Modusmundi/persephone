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


def test_cli_init_help() -> None:
    """Test CLI init help command."""
    runner = CliRunner()
    result = runner.invoke(cli, ["init", "--help"])
    assert result.exit_code == 0
    assert "Initialize AuthTest configuration and database" in result.output


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


def test_db_help() -> None:
    """Test db help command."""
    runner = CliRunner()
    result = runner.invoke(cli, ["db", "--help"])
    assert result.exit_code == 0
    assert "Manage AuthTest database" in result.output


def test_db_generate_key() -> None:
    """Test db generate-key command."""
    runner = CliRunner()
    result = runner.invoke(cli, ["db", "generate-key"])
    assert result.exit_code == 0
    # Key should be 64 hex characters (256 bits)
    assert len(result.output.strip()) == 64
