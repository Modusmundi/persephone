"""Pytest configuration and fixtures."""

from collections.abc import Generator

import pytest
from flask import Flask
from flask.testing import FlaskClient, FlaskCliRunner

from authtest.app import create_app


@pytest.fixture
def app() -> Generator[Flask, None, None]:
    """Create application for testing with auth disabled."""
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret-key",
            "AUTH_ENABLED": False,  # Disable auth for most tests
        }
    )
    yield app


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    """Create test client."""
    return app.test_client()


@pytest.fixture
def runner(app: Flask) -> FlaskCliRunner:
    """Create CLI test runner."""
    return app.test_cli_runner()
