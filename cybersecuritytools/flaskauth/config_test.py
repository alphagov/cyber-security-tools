import os
from typing import Dict

import pytest

from .config import load_ssm_parameters
from .static_site_wrapper_app import app
from .tests import stubs


@pytest.mark.usefixtures("test_ssm_parameters")
def test_load_ssm_parameters(test_ssm_parameters: Dict[str, str]) -> None:
    """
    Run a request through the lambda_handler and save the response for
    later testing.
    """
    ssm_prefix = os.environ["SSM_PREFIX"]
    stubber = stubs.mock_config_load_ssm_parameters(ssm_prefix, test_ssm_parameters)

    with stubber:
        load_ssm_parameters(app)

        for param, value in test_ssm_parameters.items():
            if param == "/flask/secret_key":
                assert app.config["SECRET_KEY"] == value
                assert app.secret_key == value
            else:
                # /oidc/client_id becomes oidc_client_id
                config_var = param.replace("/", "_")[1:]
                assert app.config[config_var] == value
