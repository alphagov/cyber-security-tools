# """ Create mock boto3 clients for testing """
from typing import Any, Dict

import boto3
from botocore.stub import Stubber  # type: ignore


def _keep_it_real() -> None:
    """ Keep the native """
    if not getattr(boto3, "real_client", None):
        boto3.real_client = boto3.client  # type: ignore


def mock_config_load_ssm_parameters(path: str, parameters: Dict[str, str]) -> Stubber:
    _keep_it_real()
    client = boto3.real_client("ssm")  # type: ignore

    stubber = Stubber(client)

    # Add responses
    stub_response_ssm_get_parameters_by_path(stubber, path, parameters)

    stubber.activate()
    # override boto.client to return the mock client
    boto3.client = lambda service, region_name=None: client  # type: ignore
    return stubber


# Responses
# Client: ssm
def stub_response_ssm_get_parameters_by_path(
    stubber: Stubber, path: str, parameters: Dict[str, Any]
) -> None:
    response_params = [
        {"Name": f"{path}{param_name}", "Value": param_value}
        for param_name, param_value in parameters.items()
    ]
    mock_get_parameters_by_path = {"Parameters": response_params}
    parameters = {"Path": path, "Recursive": True, "WithDecryption": True}

    stubber.add_response(
        "get_parameters_by_path", mock_get_parameters_by_path, parameters
    )
