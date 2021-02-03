import os
from typing import Any, Dict

import pytest

from .lambda_handler import lambda_handler
from .tests import stubs


@pytest.mark.usefixtures("request_home", "test_ssm_parameters")
def test_get_homepage(
    request_home: Dict[str, Any], test_ssm_parameters: Dict[str, str]
) -> None:
    """
    Run a request through the lambda_handler and save the response for
    later testing.
    """
    ssm_prefix = os.environ["SSM_PREFIX"]
    stubber = stubs.mock_config_load_ssm_parameters(ssm_prefix, test_ssm_parameters)

    with stubber:
        response = lambda_handler(request_home, None)

        assert isinstance(response, dict)
        assert "body" in response
        assert "statusCode" in response and response["statusCode"] == 200
        assert "headers" in response
        assert "Content-type" in response["headers"]
        stubber.deactivate()
