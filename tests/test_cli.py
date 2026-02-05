"""Tests for the CLI commands."""

import json
import os
import tempfile
from pathlib import Path

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


class TestConfigCommands:
    """Tests for config CLI commands with isolated database."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        import secrets

        self.runner = CliRunner()
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test.db"
        self.key_path = Path(self.temp_dir) / "test.key"

        # Generate a test encryption key
        self.test_key = secrets.token_hex(32)

        # Set the key directly via env var (not key file) for immediate availability
        os.environ["AUTHTEST_DB_PATH"] = str(self.db_path)
        os.environ["AUTHTEST_DB_KEY"] = self.test_key
        # Also save to file for commands that might check file existence
        self.key_path.write_text(self.test_key)
        self.key_path.chmod(0o600)
        os.environ["AUTHTEST_DB_KEY_FILE"] = str(self.key_path)

    def teardown_method(self) -> None:
        """Clean up test fixtures."""
        # Close any open database connections
        from authtest.storage.database import _db
        import authtest.storage.database as db_module
        if db_module._db is not None:
            db_module._db.close()
            db_module._db = None

        # Clear environment variables
        os.environ.pop("AUTHTEST_DB_PATH", None)
        os.environ.pop("AUTHTEST_DB_KEY_FILE", None)
        os.environ.pop("AUTHTEST_DB_KEY", None)

        # Clean up temp files
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _init_db(self) -> None:
        """Initialize the test database directly."""
        from authtest.storage import Database

        database = Database(db_path=self.db_path)
        database.init_db()
        database.close()

    def test_config_init(self) -> None:
        """Test config init command creates database when key exists but db doesn't."""
        # Key already exists from setup, but no db yet
        result = self.runner.invoke(cli, ["config", "init"])
        assert result.exit_code == 0
        assert "initialized successfully" in result.output or "already initialized" in result.output

    def test_config_init_already_initialized(self) -> None:
        """Test config init when already initialized."""
        self._init_db()
        result = self.runner.invoke(cli, ["config", "init"])
        assert result.exit_code == 0
        assert "already initialized" in result.output

    def test_config_init_force(self) -> None:
        """Test config init --force reinitializes."""
        self._init_db()
        result = self.runner.invoke(cli, ["config", "init", "--force"])
        assert result.exit_code == 0
        # Force creates a new key, overwriting our test key
        assert "initialized successfully" in result.output or "Generating" in result.output

    def test_config_init_json_output(self) -> None:
        """Test config init with JSON output shows correct status."""
        # When key and db both exist, status is already_initialized
        self._init_db()
        result = self.runner.invoke(cli, ["config", "init", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        # Could be initialized or already_initialized depending on state
        assert data["status"] in ("initialized", "already_initialized")
        assert "database" in data

    def test_config_idp_list_empty(self) -> None:
        """Test config idp list when no IdPs configured."""
        self._init_db()
        result = self.runner.invoke(cli, ["config", "idp", "list"])
        assert result.exit_code == 0
        assert "No Identity Providers configured" in result.output

    def test_config_idp_list_json_empty(self) -> None:
        """Test config idp list JSON output when empty."""
        self._init_db()
        result = self.runner.invoke(cli, ["config", "idp", "list", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["count"] == 0
        assert data["idps"] == []

    def test_config_idp_add_saml(self) -> None:
        """Test adding a SAML IdP configuration."""
        self._init_db()
        result = self.runner.invoke(
            cli,
            [
                "config", "idp", "add", "test-saml",
                "--type", "saml",
                "--display-name", "Test SAML IdP",
                "--entity-id", "https://idp.example.com",
                "--sso-url", "https://idp.example.com/sso",
                "--no-interactive",
            ],
        )
        assert result.exit_code == 0
        assert "created successfully" in result.output

    def test_config_idp_add_oidc(self) -> None:
        """Test adding an OIDC IdP configuration."""
        self._init_db()
        result = self.runner.invoke(
            cli,
            [
                "config", "idp", "add", "test-oidc",
                "--type", "oidc",
                "--display-name", "Test OIDC IdP",
                "--issuer", "https://accounts.google.com",
                "--no-interactive",
            ],
        )
        assert result.exit_code == 0
        assert "created successfully" in result.output

    def test_config_idp_add_json_output(self) -> None:
        """Test adding IdP with JSON output."""
        self._init_db()
        result = self.runner.invoke(
            cli,
            [
                "config", "idp", "add", "test-json",
                "--type", "saml",
                "--json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "created"
        assert data["idp"]["name"] == "test-json"
        assert data["idp"]["type"] == "saml"

    def test_config_idp_add_duplicate(self) -> None:
        """Test adding duplicate IdP fails."""
        self._init_db()
        self.runner.invoke(
            cli,
            ["config", "idp", "add", "dup-test", "--type", "saml", "--no-interactive"],
        )
        result = self.runner.invoke(
            cli,
            ["config", "idp", "add", "dup-test", "--type", "saml", "--no-interactive"],
        )
        assert result.exit_code != 0
        assert "already exists" in result.output

    def test_config_idp_list_with_idps(self) -> None:
        """Test config idp list with configured IdPs."""
        self._init_db()
        self.runner.invoke(
            cli,
            ["config", "idp", "add", "idp1", "--type", "saml", "--no-interactive"],
        )
        self.runner.invoke(
            cli,
            ["config", "idp", "add", "idp2", "--type", "oidc", "--no-interactive"],
        )

        result = self.runner.invoke(cli, ["config", "idp", "list"])
        assert result.exit_code == 0
        assert "idp1" in result.output
        assert "idp2" in result.output
        assert "(saml)" in result.output
        assert "(oidc)" in result.output

    def test_config_idp_show(self) -> None:
        """Test config idp show command."""
        self._init_db()
        self.runner.invoke(
            cli,
            [
                "config", "idp", "add", "show-test",
                "--type", "saml",
                "--entity-id", "https://idp.example.com",
                "--no-interactive",
            ],
        )

        result = self.runner.invoke(cli, ["config", "idp", "show", "show-test"])
        assert result.exit_code == 0
        assert "show-test" in result.output
        assert "Entity ID:" in result.output
        assert "https://idp.example.com" in result.output

    def test_config_idp_show_json(self) -> None:
        """Test config idp show with JSON output."""
        self._init_db()
        self.runner.invoke(
            cli,
            [
                "config", "idp", "add", "show-json",
                "--type", "saml",
                "--entity-id", "https://idp.example.com",
                "--no-interactive",
            ],
        )

        result = self.runner.invoke(cli, ["config", "idp", "show", "show-json", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["name"] == "show-json"
        assert data["type"] == "saml"
        assert data["saml"]["entity_id"] == "https://idp.example.com"

    def test_config_idp_show_not_found(self) -> None:
        """Test config idp show for non-existent IdP."""
        self._init_db()
        result = self.runner.invoke(cli, ["config", "idp", "show", "nonexistent"])
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_config_idp_edit(self) -> None:
        """Test config idp edit command."""
        self._init_db()
        self.runner.invoke(
            cli,
            ["config", "idp", "add", "edit-test", "--type", "saml", "--no-interactive"],
        )

        result = self.runner.invoke(
            cli,
            [
                "config", "idp", "edit", "edit-test",
                "--display-name", "Updated Name",
                "--sso-url", "https://new-sso.example.com",
            ],
        )
        assert result.exit_code == 0
        assert "updated" in result.output

        # Verify changes
        show_result = self.runner.invoke(cli, ["config", "idp", "show", "edit-test", "--json"])
        data = json.loads(show_result.output)
        assert data["display_name"] == "Updated Name"
        assert data["saml"]["sso_url"] == "https://new-sso.example.com"

    def test_config_idp_edit_enable_disable(self) -> None:
        """Test enabling and disabling an IdP."""
        self._init_db()
        self.runner.invoke(
            cli,
            ["config", "idp", "add", "toggle-test", "--type", "saml", "--no-interactive"],
        )

        # Disable
        result = self.runner.invoke(
            cli,
            ["config", "idp", "edit", "toggle-test", "--disabled"],
        )
        assert result.exit_code == 0

        show_result = self.runner.invoke(cli, ["config", "idp", "show", "toggle-test", "--json"])
        data = json.loads(show_result.output)
        assert data["enabled"] is False

        # Re-enable
        result = self.runner.invoke(
            cli,
            ["config", "idp", "edit", "toggle-test", "--enabled"],
        )
        assert result.exit_code == 0

        show_result = self.runner.invoke(cli, ["config", "idp", "show", "toggle-test", "--json"])
        data = json.loads(show_result.output)
        assert data["enabled"] is True

    def test_config_idp_remove(self) -> None:
        """Test config idp remove command."""
        self._init_db()
        self.runner.invoke(
            cli,
            ["config", "idp", "add", "remove-test", "--type", "saml", "--no-interactive"],
        )

        result = self.runner.invoke(
            cli,
            ["config", "idp", "remove", "remove-test", "--force"],
        )
        assert result.exit_code == 0
        assert "removed" in result.output

        # Verify removal
        list_result = self.runner.invoke(cli, ["config", "idp", "list", "--json"])
        data = json.loads(list_result.output)
        assert data["count"] == 0

    def test_config_idp_remove_not_found(self) -> None:
        """Test removing non-existent IdP."""
        self._init_db()
        result = self.runner.invoke(
            cli,
            ["config", "idp", "remove", "nonexistent", "--force"],
        )
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_config_export_import(self) -> None:
        """Test config export and import commands."""
        self._init_db()

        # Add some IdPs
        self.runner.invoke(
            cli,
            [
                "config", "idp", "add", "export-saml",
                "--type", "saml",
                "--entity-id", "https://saml.example.com",
                "--no-interactive",
            ],
        )
        self.runner.invoke(
            cli,
            [
                "config", "idp", "add", "export-oidc",
                "--type", "oidc",
                "--issuer", "https://oidc.example.com",
                "--no-interactive",
            ],
        )

        # Export
        export_path = Path(self.temp_dir) / "export.json"
        result = self.runner.invoke(cli, ["config", "export", str(export_path)])
        assert result.exit_code == 0
        assert export_path.exists()

        # Verify export content
        export_data = json.loads(export_path.read_text())
        assert export_data["version"] == "1.0"
        assert len(export_data["idp_providers"]) == 2

        # Clear database by reinitializing
        if self.db_path.exists():
            self.db_path.unlink()
        self._init_db()

        # Import
        result = self.runner.invoke(cli, ["config", "import", str(export_path)])
        assert result.exit_code == 0
        assert "Imported" in result.output

        # Verify import
        list_result = self.runner.invoke(cli, ["config", "idp", "list", "--json"])
        data = json.loads(list_result.output)
        assert data["count"] == 2

    def test_config_export_json_output(self) -> None:
        """Test config export with JSON output."""
        self._init_db()
        export_path = Path(self.temp_dir) / "export2.json"
        result = self.runner.invoke(cli, ["config", "export", str(export_path), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "exported"
        assert "counts" in data

    def test_config_import_dry_run(self) -> None:
        """Test config import with dry-run."""
        self._init_db()

        # Add an IdP and export
        self.runner.invoke(
            cli,
            ["config", "idp", "add", "dry-run-test", "--type", "saml", "--no-interactive"],
        )
        export_path = Path(self.temp_dir) / "dry-run.json"
        self.runner.invoke(cli, ["config", "export", str(export_path)])

        # Clear database by reinitializing
        if self.db_path.exists():
            self.db_path.unlink()
        self._init_db()

        result = self.runner.invoke(cli, ["config", "import", str(export_path), "--dry-run"])
        assert result.exit_code == 0
        assert "Would import" in result.output

        # Verify nothing was actually imported
        list_result = self.runner.invoke(cli, ["config", "idp", "list", "--json"])
        data = json.loads(list_result.output)
        assert data["count"] == 0

    def test_config_import_replace_mode(self) -> None:
        """Test config import with replace mode."""
        self._init_db()

        # Add some IdPs
        self.runner.invoke(
            cli,
            ["config", "idp", "add", "original", "--type", "saml", "--no-interactive"],
        )

        # Export with one IdP
        export_path = Path(self.temp_dir) / "replace.json"
        self.runner.invoke(cli, ["config", "export", str(export_path)])

        # Add another IdP
        self.runner.invoke(
            cli,
            ["config", "idp", "add", "extra", "--type", "oidc", "--no-interactive"],
        )

        # Verify we have 2 IdPs
        list_result = self.runner.invoke(cli, ["config", "idp", "list", "--json"])
        data = json.loads(list_result.output)
        assert data["count"] == 2

        # Import with replace - should only have the original IdP
        result = self.runner.invoke(cli, ["config", "import", str(export_path), "--replace"])
        assert result.exit_code == 0

        list_result = self.runner.invoke(cli, ["config", "idp", "list", "--json"])
        data = json.loads(list_result.output)
        assert data["count"] == 1
        assert data["idps"][0]["name"] == "original"


class TestConfigWithoutInit:
    """Tests for config commands without database initialization."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.runner = CliRunner()
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "nonexistent.db"
        self.key_path = Path(self.temp_dir) / "nonexistent.key"

        # Set environment variables for non-existent database
        os.environ["AUTHTEST_DB_PATH"] = str(self.db_path)
        os.environ["AUTHTEST_DB_KEY_FILE"] = str(self.key_path)

    def teardown_method(self) -> None:
        """Clean up test fixtures."""
        os.environ.pop("AUTHTEST_DB_PATH", None)
        os.environ.pop("AUTHTEST_DB_KEY_FILE", None)
        if self.db_path.exists():
            self.db_path.unlink()
        if self.key_path.exists():
            self.key_path.unlink()
        Path(self.temp_dir).rmdir()

    def test_idp_list_without_init(self) -> None:
        """Test idp list fails gracefully without initialization."""
        result = self.runner.invoke(cli, ["config", "idp", "list"])
        assert result.exit_code != 0
        assert "config init" in result.output.lower()

    def test_idp_add_without_init(self) -> None:
        """Test idp add fails gracefully without initialization."""
        result = self.runner.invoke(
            cli,
            ["config", "idp", "add", "test", "--type", "saml", "--no-interactive"],
        )
        assert result.exit_code != 0
        assert "config init" in result.output.lower()

    def test_config_export_without_init(self) -> None:
        """Test export fails gracefully without initialization."""
        export_path = Path(self.temp_dir) / "export.json"
        result = self.runner.invoke(cli, ["config", "export", str(export_path)])
        assert result.exit_code != 0
        assert "config init" in result.output.lower()
