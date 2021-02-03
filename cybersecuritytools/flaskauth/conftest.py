import os
from typing import Any, Dict

import pytest
from flask import Flask
from flask.testing import FlaskClient


def get_test_client(app: Flask) -> FlaskClient:  # type: ignore
    # Flask provides a way to test your application by exposing the Werkzeug test Client
    # and handling the context locals for you.
    testing_client = app.test_client()

    # Establish an application context before running the tests.
    ctx = app.app_context()
    ctx.push()

    return testing_client  # this is where the testing happens!


@pytest.fixture()
def kid() -> str:
    "The Key ID we expect for the above public key"
    return "307a30c3-8280-4ff5-a78d-6bc5263ffbe8"


@pytest.fixture()
def request_home() -> Dict[str, Any]:
    group = "target_group_x/123456"
    account = "123456789012"
    service = "elasticloadbalancing"
    target_group = f"arn:aws:{service}:eu-west-2:{account}:targetgroup/{group}"
    user_agent = "Mozilla/5.0"
    return {
        "requestContext": {"elb": {"targetGroupArn": target_group}},
        "httpMethod": "GET",
        "path": "/",
        "queryStringParameters": {},
        "headers": {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "en-GB,en;q=0.5",
            "host": "test.gds-cyber-security.digital",
            "upgrade-insecure-requests": "1",
            "user-agent": user_agent,
            "x-forwarded-for": "81.104.91.14",
            "x-forwarded-port": "443",
            "x-forwarded-proto": "https",
        },
        "body": "",
        "isBase64Encoded": True,
    }


def get_oidc_root() -> str:
    return "https://oidc.test.domain/auth/root/"


@pytest.fixture()
def test_ssm_parameters() -> Dict[str, Any]:
    return {
        "/flask/secret_key": "flask-secret",
        "/oidc/endpoint": get_oidc_root(),
        "/oidc/client_id": "oidc-client-id",
        "/oidc/client_secret": "oidc-client-secret",  # pragma: allowlist secret
    }


@pytest.fixture()
def static_home() -> str:
    module_path = os.path.dirname(os.path.abspath(__file__))
    with open(f"{module_path}/tests/static/index.html", "r") as page_file:
        page_content = page_file.read()
    return page_content


@pytest.fixture()
def access_controls() -> Dict[str, Any]:
    controls = {
        "paths": {
            "/index.html": {"open_access": True},
            "/user-role-one": {
                "message": "You need to be granted the incident-management role.",
                "open_access": False,
                "role_requirements": [{"type": "all", "roles": ["user-role-1"]}],
            },
            "/user-role-two": {
                "message": "You need to be granted the incident-management role.",
                "open_access": False,
                "role_requirements": [{"type": "all", "roles": ["user-role-2"]}],
            },
            "/user-role-any": {
                "message": "You need to be granted the incident-management role.",
                "open_access": False,
                "role_requirements": [
                    {"type": "any", "roles": ["user-role-1", "user-role-2"]}
                ],
            },
            "/user-role-all": {
                "message": "You need to be granted the incident-management role.",
                "open_access": False,
                "role_requirements": [
                    {"type": "all", "roles": ["user-role-1", "user-role-2"]}
                ],
            },
            "/user-role-split": {
                "message": "You need to be granted the incident-management role.",
                "open_access": False,
                "role_requirements": [
                    {"type": "any", "roles": ["user-role-1", "user-role-2"]},
                    {"type": "all", "roles": ["user-role-3"]},
                ],
            },
        }
    }
    return controls


def get_default_session() -> Dict[str, Any]:
    session = {
        "state": "abc123",
        "user_info": {
            "name": "Test User",
            "email": "test.user@test-domain.com",
            "roles": ["user-role-1"],
        },
    }
    return session


@pytest.fixture()
def test_session() -> Dict[str, Any]:
    return get_default_session()


@pytest.fixture()
def openid_config() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    with open(f"{here}/tests/mock/openid-configuration.json", "r") as config:
        content = config.read()
    return content
