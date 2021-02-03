import base64
import json
from typing import Any, Dict

import jwt
import requests

from cybersecuritytools.jsonlogger import LOG

# https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html

PUBLIC_KEYS: Dict[str, Any] = {}


def get_kid(encoded_jwt: str) -> Any:
    """
    Get the ALB (K)ey (ID) from a JWT

    Example 'kid': '307a30c3-8280-4ff5-a78d-6bc5263ffbe8'
    """
    LOG.debug("get_kid")
    jwt_headers = encoded_jwt.split(".")[0]
    decoded_jwt_headers = base64.b64decode(jwt_headers).decode("utf-8")
    decoded_json = json.loads(decoded_jwt_headers)
    kid = decoded_json["kid"]
    return kid


def get_public_key(kid: str, region: str = "eu-west-2") -> str:
    """
    Get an ALB public key from a keyID
    """
    LOG.debug("get_public_key")
    url = f"https://public-keys.auth.elb.{region}.amazonaws.com/{kid}"
    req = requests.get(url)
    public_key = req.text
    return public_key


def alb_get_user_info(encoded_jwt: str, verify: bool = True) -> Dict[str, Any]:
    """
    Process a JWT token to check that it is valid
    """
    LOG.debug("alb_get_user_info")
    LOG.debug(encoded_jwt)
    kid = get_kid(encoded_jwt)
    public_key = PUBLIC_KEYS.get(kid, None)
    if not public_key:
        public_key = get_public_key(kid)
        PUBLIC_KEYS[kid] = public_key
    payload = jwt.decode(
        encoded_jwt, public_key, algorithms=["ES256"], options={"verify_exp": verify}
    )
    return payload
