import json
import os
import urllib.parse
from typing import Dict

import pytest
import requests_mock  # type: ignore

from cybersecuritytools.jsonlogger import LOG

from .conftest import get_oidc_root
from .oidc_client import (
    CONFIG,
    get_authorization_url,
    get_client,
    get_host,
    get_session_state,
    set_oidc_config,
)
from .static_site_wrapper_app import bootstrap
from .tests import stubs


@pytest.mark.usefixtures("test_ssm_parameters")
def test_get_host(test_ssm_parameters: Dict[str, str]) -> None:
    ssm_prefix = os.environ["SSM_PREFIX"]
    stubber = stubs.mock_config_load_ssm_parameters(ssm_prefix, test_ssm_parameters)

    with stubber, requests_mock.Mocker():
        app = bootstrap()
        with app.test_request_context("/"):
            host = get_host()
            assert (
                host == "http://localhost/"
            ), "Get host should return a domain with protocol and trailing slash."


def test_set_oidc_config() -> None:
    oidc_root = get_oidc_root()
    set_oidc_config(
        endpoint=oidc_root,
        client_id="client",
        client_secret="secret",
    )
    assert (
        CONFIG["endpoint"] == oidc_root
    ), "Arguments should be passed through to CONFIG"
    assert (
        CONFIG["client_id"] == "client"
    ), "Arguments should be passed through to CONFIG"
    assert (
        CONFIG["client_secret"] == "secret"
    ), "Arguments should be passed through to CONFIG"
    assert (
        CONFIG["scope"] == "openid profile email roles"
    ), "Default scope should be set"
    set_oidc_config(
        endpoint=oidc_root,
        client_id="client",
        client_secret="secret",
        scope="openid email",
    )
    assert CONFIG["scope"] == "openid email", "Scope can be overridden if specified"


@pytest.mark.usefixtures("openid_config", "test_ssm_parameters")
def test_get_client(openid_config: str, test_ssm_parameters: Dict[str, str]) -> None:
    ssm_prefix = os.environ["SSM_PREFIX"]
    stubber = stubs.mock_config_load_ssm_parameters(ssm_prefix, test_ssm_parameters)

    with stubber, requests_mock.Mocker() as mock_requests:
        config_file = json.loads(openid_config)
        app = bootstrap()
        oidc_root = app.config["oidc_endpoint"]
        LOG.debug(oidc_root)
        config_url = f"{oidc_root}.well-known/openid-configuration"
        mock_requests.get(config_url, text=openid_config)
        client = get_client()
        assert (
            client.authorization_endpoint == config_file["authorization_endpoint"]
        ), "The client should be configured with urls from the openid-condfiguration.json"  # noqa


@pytest.mark.usefixtures("test_ssm_parameters")
def test_get_session_state(test_ssm_parameters: Dict[str, str]) -> None:
    ssm_prefix = os.environ["SSM_PREFIX"]
    stubber = stubs.mock_config_load_ssm_parameters(ssm_prefix, test_ssm_parameters)

    with stubber, requests_mock.Mocker():
        app = bootstrap()
        with app.test_request_context("/"):
            state_1 = get_session_state()
            state_2 = get_session_state()
            assert (
                state_1 == state_2
            ), "Repeated calls should return the same state value"
            state_3 = get_session_state(True)
            assert state_2 != state_3, "Forcing renew should generate a different value"
            state_4 = get_session_state()
            assert (
                state_3 == state_4
            ), "After a forced renew, subsequent calls should result in the same value"


@pytest.mark.usefixtures("openid_config", "test_ssm_parameters")
def test_get_authorization_url(
    openid_config: str, test_ssm_parameters: Dict[str, str]
) -> None:
    """
    https://oidc.test.domain/auth/root/protocol/openid-connect/auth
    ?client_id=oidc-client-id
    &response_type=code
    &scope=openid+profile+email+roles
    &nonce=pRcWtmMvflRUe1Bv
    &redirect_uri=https%3A%2F%2Flocalhost%2F
    &state=4J5LSMQMWJTzHATzdi1BVn6KMcz7Jhwqxn1sAHVs6YVRmLzcokXkibrn4ymITsNk
    """
    ssm_prefix = os.environ["SSM_PREFIX"]
    stubber = stubs.mock_config_load_ssm_parameters(ssm_prefix, test_ssm_parameters)

    with stubber, requests_mock.Mocker() as mock_requests:
        app = bootstrap()
        client_id = app.config.get("oidc_client_id")
        oidc_root = app.config["oidc_endpoint"]
        LOG.debug(oidc_root)
        config_url = f"{oidc_root}.well-known/openid-configuration"
        mock_requests.get(config_url, text=openid_config)
        with app.test_request_context("/"):
            redirect = "https://localhost/"
            encoded_redirect = urllib.parse.quote_plus(redirect)
            scope = urllib.parse.quote_plus(CONFIG["scope"])
            state = get_session_state()
            auth_url = get_authorization_url(redirect)
            assert auth_url.startswith(
                oidc_root
            ), "Auth url should point to the oidc provider."
            assert (
                f"?client_id={client_id}" in auth_url
            ), "Auth url should contain the client_id."
            assert (
                f"&redirect_uri={encoded_redirect}" in auth_url
            ), "Auth url should contain the redirect uri encoded."
            assert (
                f"&state={state}" in auth_url
            ), "Auth url should contain session state."
            assert (
                "&response_type=code" f"&scope={scope}" "&nonce="
            ) in auth_url, "Auth url should contain response_type, scope and nonce."
