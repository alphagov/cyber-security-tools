import json
from urllib.parse import urlencode

from flask import *
from jsonlogger import LOG
from oic import rndstr
from oic.oauth2 import AuthorizationResponse, OauthMessageFactory, Grant
from oic.oic import Client
from oic.exception import AccessDenied
from oic.utils.authn.client import ClientSecretBasic, ClientSecretPost

CONFIG = {}


def get_host():
    host = request.host_url
    return host


def set_oidc_config(endpoint, client_id, client_secret, scope="openid profile email roles"):
    LOG.debug(f"Set oidc config for: {endpoint}")
    CONFIG["endpoint"] = endpoint
    CONFIG["client_id"] = client_id
    CONFIG["client_secret"] = client_secret
    CONFIG["scope"] = scope
    CONFIG["state"] = rndstr(size=128)


def get_client():

    client = CONFIG.get("client")
    if "endpoint" in CONFIG and not client:
        # Check CONFIG has a client key and it is not None
        LOG.debug(f"Create OIDC client for: {CONFIG['endpoint']}")
        client = Client(
            client_authn_method={
                'client_secret_post': ClientSecretPost,
                'client_secret_basic': ClientSecretBasic
            }
        )
        # client.set_session(session)
        client.provider_config(CONFIG["endpoint"])
        client.client_id = CONFIG["client_id"]
        client.client_secret = CONFIG["client_secret"]

        CONFIG["client"] = client

    return CONFIG["client"]


def get_authorization_url(redirect_to):
    """
    Get login url
    """
    LOG.debug("Get OIDC authorization URL")
    nonce = rndstr()
    client = get_client()

    url = None
    if client:
        args = {
            'client_id': client.client_id,
            'response_type': 'code',
            'scope': CONFIG["scope"],
            'nonce': nonce,
            'redirect_uri': redirect_to,
            'state': CONFIG["state"]
        }
        url = client.provider_info['authorization_endpoint'] + '?' + urlencode(args, True)
    else:
        LOG.error("OIDC client not initialised")

    return url


def get_access_token(auth_response, redirect_to):
    """
    Get an access token
    """

    if auth_response["state"] != CONFIG["state"]:
        raise AccessDenied("State tampering")
    else:
        client = get_client()
        LOG.debug(f"Auth response code: {auth_response['code']}")
        LOG.debug(f"Auth response session_state: {auth_response['session_state']}")
        args = {
            'code': auth_response['code'],
            'client_id': client.client_id,
            'client_secret': client.client_secret,
            'redirect_uri': redirect_to
        }
        token_response = client.do_access_token_request(
            scope=CONFIG["scope"],
            state=auth_response['state'],
            request_args=args,
            authn_method='client_secret_post')

        LOG.debug("Token response: " + str(token_response))
        CONFIG["token"] = token_response

    return token_response


def get_user_roles(token):
    """
    Get roles list from user_info
    """
    token_dict = token.to_dict()
    try:
        roles = token_dict["id_token"]["realm_access"]["roles"]
    except (KeyError, ValueError):
        roles = []
    return roles


def get_userinfo(auth_response, redirect_to):
    """
    Make userinfo request
    """
    try:
        client = get_client()
        token = get_access_token(auth_response, redirect_to)
        LOG.debug(token.to_dict())

        roles = get_user_roles(token)

        user_info = client.do_user_info_request(
            state=auth_response['state'],
            authn_method='client_secret_post')
        user_info_dict = user_info.to_dict()
        user_info_dict["roles"] = roles
    except AccessDenied:
        user_info_dict = None
    return user_info_dict


def get_authorization_response():
    """
    Parse authorization response
    """
    client = get_client()
    authorization_response = client.parse_response(
        AuthorizationResponse,
        info=request.args,
        sformat='dict'
    )
    return authorization_response


def get_logout_redirect(redirect_to):
    headers = {}
    headers['Content-Type'] = 'application/json'
    # I don't think we need an auth header since we're actually
    # redirecting to the site rather than making an API call

    # headers['Authorization'] = 'Token %s' % CONFIG["token"]
    client = get_client()
    args = {
        "redirect_uri": redirect_to
    }
    logout_url = client.provider_info['end_session_endpoint'] + '?' + urlencode(args, True)

    if 'user_info' in session:
        del session['user_info']

    response = redirect(logout_url)
    return response


def reset_config():
    del CONFIG["token"]