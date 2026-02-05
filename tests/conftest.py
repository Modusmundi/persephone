"""Pytest configuration and fixtures."""

import pytest
from flask import Flask
from flask.testing import FlaskClient

from authtest.app import create_app


@pytest.fixture
def app() -> Flask:
    """Create application for testing."""
    app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret-key",
        }
    )
    yield app


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    """Create test client."""
    return app.test_client()


@pytest.fixture
def runner(app: Flask):
    """Create CLI test runner."""
    return app.test_cli_runner()
