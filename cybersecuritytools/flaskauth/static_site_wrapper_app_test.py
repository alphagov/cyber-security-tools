import os
from typing import Any, Dict, Optional

import pytest

from .auth import set_access_controls
from .conftest import get_test_client
from .static_site_wrapper_app import bootstrap  # noqa
from .tests import stubs


@pytest.mark.usefixtures("test_session", "test_ssm_parameters", "access_controls")
def test_route_user_role_1(
    test_session: Dict[str, Any],
    test_ssm_parameters: Dict[str, Any],
    access_controls: Dict[str, Any],
) -> None:
    ssm_prefix = os.environ["SSM_PREFIX"]
    stubber = stubs.mock_config_load_ssm_parameters(ssm_prefix, test_ssm_parameters)

    expected_access = {
        "/": True,
        "/user-role-one.html": True,
        "/user-role-one/sub-page.html": True,
        "/user-role-two.html": False,
        "/user-role-any.html": True,
        "/user-role-all.html": False,
        "/user-role-split.html": False,
    }
    with stubber:
        expect_access(test_session, access_controls, expected_access)


@pytest.mark.usefixtures("test_session", "test_ssm_parameters", "access_controls")
def test_route_user_role_2(
    test_session: Dict[str, Any],
    test_ssm_parameters: Dict[str, Any],
    access_controls: Dict[str, Any],
) -> None:
    ssm_prefix = os.environ["SSM_PREFIX"]
    test_session["user_info"]["roles"] = ["user-role-2"]
    stubber = stubs.mock_config_load_ssm_parameters(ssm_prefix, test_ssm_parameters)

    expected_access = {
        "/": True,
        "/user-role-one.html": False,
        "/user-role-one/sub-page.html": False,
        "/user-role-two.html": True,
        "/user-role-any.html": True,
        "/user-role-all.html": False,
        "/user-role-split.html": False,
    }
    with stubber:
        expect_access(test_session, access_controls, expected_access)


@pytest.mark.usefixtures("test_session", "test_ssm_parameters", "access_controls")
def test_route_user_role_all(
    test_session: Dict[str, Any],
    test_ssm_parameters: Dict[str, Any],
    access_controls: Dict[str, Any],
) -> None:
    ssm_prefix = os.environ["SSM_PREFIX"]
    test_session["user_info"]["roles"] = ["user-role-1", "user-role-2", "user-role-3"]
    stubber = stubs.mock_config_load_ssm_parameters(ssm_prefix, test_ssm_parameters)

    expected_access = {
        "/": True,
        "/user-role-one.html": True,
        "/user-role-one/sub-page.html": True,
        "/user-role-two.html": True,
        "/user-role-any.html": True,
        "/user-role-all.html": True,
        "/user-role-split.html": True,
    }
    with stubber:
        expect_access(test_session, access_controls, expected_access)


@pytest.mark.usefixtures("test_ssm_parameters", "access_controls")
def test_route_logged_out(
    test_ssm_parameters: Dict[str, Any], access_controls: Dict[str, Any]
) -> None:
    ssm_prefix = os.environ["SSM_PREFIX"]
    stubber = stubs.mock_config_load_ssm_parameters(ssm_prefix, test_ssm_parameters)

    expected_access = {
        "/": True,
        "/user-role-one.html": False,
        "/user-role-one/sub-page.html": False,
        "/user-role-two.html": False,
        "/user-role-any.html": False,
        "/user-role-all.html": False,
        "/user-role-split.html": False,
    }
    with stubber:
        expect_access({}, access_controls, expected_access)


@pytest.mark.usefixtures("test_ssm_parameters", "access_controls")
def test_route_assets(
    test_ssm_parameters: Dict[str, Any], access_controls: Dict[str, Any]
) -> None:
    ssm_prefix = os.environ["SSM_PREFIX"]
    stubber = stubs.mock_config_load_ssm_parameters(ssm_prefix, test_ssm_parameters)

    expected_access = {
        "/assets/favicon.ico": True,
        "/assets/govuk-crest.png": True,
        "/assets/font.woff": True,
        "/assets/font.woff2": True,
        "/assets/test.css": True,
        "/assets/test.js": True,
    }
    with stubber:
        expect_access({}, access_controls, expected_access)


def expect_access(
    test_session: Dict[str, Any],
    access_controls: Dict[str, Any],
    expected_access: Dict[str, bool],
    binary: bool = False,
) -> None:
    app = bootstrap()
    test_client = get_test_client(app)
    # mypy is wrong sessions_transaction does return a session.
    with test_client.session_transaction() as client_session:  # type: ignore
        client_session.update(test_session)

    set_access_controls(access_controls)

    logged_in = "user_info" in test_session

    for route, allow in expected_access.items():
        ext = route.split(".").pop()
        is_text_asset = ext in ["css", "js"]
        is_binary = ext in ["ico", "png", "woff", "woff2"]

        response = test_client.get(route)
        assert response.status_code == 200
        if is_binary or is_text_asset:
            assert response.content_type != "text/html"
        else:
            # html pages check content rendered correctly
            body = response.data.decode()
            assert response.content_type == "text/html"

            check_access_denied_component(allow, body)
            check_login_component(logged_in, body, test_session.get("user_info"))


def check_access_denied_component(allow: bool, body: str) -> None:
    if allow:
        assert "Access granted" in body
    else:
        assert "Access granted" not in body


def check_login_component(
    logged_in: bool, body: str, user_info: Optional[Dict[str, Any]]
) -> None:
    if logged_in:
        assert isinstance(user_info, dict)
        assert f"Logged in as: {user_info['name']}" in body
        assert "Logout" in body
    else:
        assert "Login" in body
