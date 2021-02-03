from typing import Any, Dict, Union

import serverless_wsgi  # type: ignore

from .static_site_wrapper_app import bootstrap


def lambda_handler(event: Dict[str, Any], context: Union[None, Dict[str, Any]]) -> Any:
    """
    Lambda handler entry point
    """
    return serverless_wsgi.handle_request(bootstrap(), event, context)
