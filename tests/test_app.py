"""Tests for the Flask application."""

from flask.testing import FlaskClient


def test_health_endpoint(client: FlaskClient) -> None:
    """Test the health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json == {"status": "healthy"}


def test_index_page(client: FlaskClient) -> None:
    """Test the index page loads."""
    response = client.get("/")
    assert response.status_code == 200
    assert b"AuthTest" in response.data
