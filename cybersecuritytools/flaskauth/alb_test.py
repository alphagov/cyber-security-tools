# import pytest
#
# from .alb import get_kid
#
#
# @pytest.mark.usefixtures("kid")
# def test_get_kid(encoded_jwt: str, kid: str) -> None:
#     """Check the Key ID from the encoded_jwt token is what we expect"""
#     result = get_kid(encoded_jwt)
#     assert kid == result
