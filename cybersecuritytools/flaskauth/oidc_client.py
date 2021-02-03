from typing import Any, Dict, Union
from urllib.parse import urlencode

from flask import Response, redirect, request, session
from flask.wrappers import Response as FlaskWrapperResponse
from oic import rndstr
from oic.exception import AccessDenied
from oic.oauth2.message import Message
from oic.oic import Client
from oic.oic.message import AccessTokenResponse, AuthorizationResponse
from oic.utils.authn.client import ClientSecretBasic, ClientSecretPost
from werkzeug.wrappers import Response as WerkzeugResponse

from cybersecuritytools.jsonlogger import LOG

FlaskResponse = Union[Response, WerkzeugResponse, FlaskWrapperResponse]

CONFIG: Dict[str, Any] = {}


def get_host() -> str:
    host = request.host_url
    return host


def set_oidc_config(
    endpoint: Union[str, None],
    client_id: Union[str, None],
    client_secret: Union[str, None],
    scope: str = "openid profile email roles",
) -> None:
    LOG.debug(f"Set oidc config for: {endpoint}")
    CONFIG["endpoint"] = endpoint
    CONFIG["client_id"] = client_id
    CONFIG["client_secret"] = client_secret
    CONFIG["scope"] = scope


def get_client() -> Any:
    """
    Create a client instance once and store in CONFIG for re-use

    This should always return either a Client instance or None
    Since I've used a single CONFIG dict to store the re-usable
    config mypy thinks the type of CONFIG["client"] is Any.
    """

    client = CONFIG.get("client")
    if "endpoint" in CONFIG and not client:
        # Check CONFIG has a client key and it is not None
        LOG.debug(f"Create OIDC client for: {CONFIG['endpoint']}")
        client = Client(
            client_authn_method={
                "client_secret_post": ClientSecretPost,
                "client_secret_basic": ClientSecretBasic,
            }
        )
        # client.set_session(session)
        client.provider_config(CONFIG["endpoint"])
        client.client_id = CONFIG["client_id"]
        client.client_secret = CONFIG["client_secret"]

        CONFIG["client"] = client

    return CONFIG["client"]


def get_session_state(renew: bool = False) -> Any:
    """
    Create a random string and store in flask session

    You should always retrieve the existing state
    unless you explicity force a renew.

    The return type is string but rndstr() doesn't
    declare a return type so I can't set it
    """
    if "state" not in session or renew:
        session["state"] = rndstr(size=64)  # type: ignore
    return session["state"]


def get_authorization_url(redirect_to: str) -> str:
    """
    Get login url
    """
    LOG.debug("Get OIDC authorization URL")
    nonce = rndstr()  # type: ignore
    client = get_client()

    if not client:
        LOG.error("OIDC client not initialised")
        raise BaseException  # TODO Fix exception

    args = {
        "client_id": client.client_id,
        "response_type": "code",
        "scope": CONFIG["scope"],
        "nonce": nonce,
        "redirect_uri": redirect_to,
        "state": get_session_state(),
    }
    url: str = (
        client.provider_info["authorization_endpoint"] + "?" + urlencode(args, True)
    )

    return url


def get_access_token(auth_response: Message, redirect_to: str) -> Any:
    """
    Get an access token

    This function returns an AccessTokenResponse but because
    I'm using the shared CONFIG dictionary to store it I can't
    specify it.
    """

    if auth_response["state"] != get_session_state():
        raise AccessDenied("State tampering")  # type: ignore
    else:
        client = get_client()
        LOG.debug(f"Auth response code: {auth_response['code']}")
        LOG.debug(f"Auth response session_state: {auth_response['session_state']}")
        args = {
            "code": auth_response["code"],
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "redirect_uri": redirect_to,
        }
        token_response = client.do_access_token_request(
            scope=CONFIG["scope"],
            state=auth_response["state"],
            request_args=args,
            authn_method="client_secret_post",
        )

        LOG.debug("Token response: " + str(token_response))
        CONFIG["token"] = token_response

    return token_response


def get_user_roles(token: AccessTokenResponse) -> Any:
    """
    Get roles list from user_info

    This function returns List[str] but I can't specify
    the internal types of the AccessTokenResponse.to_dict()
    """
    token_dict = token.to_dict()  # type: ignore
    try:
        roles = token_dict["id_token"]["realm_access"]["roles"]
    except (KeyError, ValueError):
        roles = []
    return roles


def get_userinfo(auth_response: Message, redirect_to: str) -> Any:
    """
    Make userinfo request
    """
    try:
        client = get_client()
        token = get_access_token(auth_response, redirect_to)
        LOG.debug(token.to_dict())

        roles = get_user_roles(token)

        user_info = client.do_user_info_request(
            state=auth_response["state"], authn_method="client_secret_post"
        )
        user_info_dict = user_info.to_dict()
        user_info_dict["roles"] = roles
    except AccessDenied as error:
        # rotate session state
        LOG.error("Login failed: %s", str(error))
        get_session_state(True)
        user_info_dict = None
    return user_info_dict


def get_authorization_response() -> Any:
    """
    Parse authorization response

    Actually returns a oic.oauth2.message.Message
    """
    client = get_client()
    authorization_response = client.parse_response(
        AuthorizationResponse, info=request.args, sformat="dict"
    )
    return authorization_response


def get_logout_redirect(redirect_to: str) -> FlaskResponse:
    headers = {}
    headers["Content-Type"] = "application/json"
    # I don't think we need an auth header since we're actually
    # redirecting to the site rather than making an API call

    # headers['Authorization'] = 'Token %s' % CONFIG["token"]
    client = get_client()
    args = {"redirect_uri": redirect_to}
    logout_url = (
        client.provider_info["end_session_endpoint"] + "?" + urlencode(args, True)
    )

    response = redirect(logout_url)
    return response
