import os
from typing import Dict

import pytest
import requests_mock  # type: ignore

from .auth import get_static_site_root, make_default_response, set_static_site_root
from .static_site_wrapper_app import bootstrap
from .tests import stubs


@pytest.mark.usefixtures("test_ssm_parameters")
def test_make_default_response(test_ssm_parameters: Dict[str, str]) -> None:
    ssm_prefix = os.environ.get("SSM_PREFIX", "/static-site")
    stubber = stubs.mock_config_load_ssm_parameters(ssm_prefix, test_ssm_parameters)

    with stubber, requests_mock.Mocker():
        app = bootstrap()
        with app.test_request_context("/"):
            response = make_default_response("/")
            body = response.data.decode()
            assert response.status_code == 200
            assert "text/html" in response.content_type  # type: ignore
            assert "Access granted" in body

        with pytest.raises(FileNotFoundError):
            make_default_response("/not-found.html")


def test_set_static_site_root() -> None:
    set_root = "/static"
    set_static_site_root(set_root)
    get_root = get_static_site_root()
    assert get_root == set_root

    set_root = "./static"
    set_static_site_root(set_root)
    get_root = get_static_site_root() or ""
    assert get_root != set_root
    assert get_root != ""
    assert get_root.endswith(set_root)
