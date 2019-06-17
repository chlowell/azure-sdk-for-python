# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE.txt in the project root for
# license information.
# -------------------------------------------------------------------------
# pylint:disable=protected-access
from azure.core import HttpRequest
try:
    from unittest.mock import Mock
except ImportError:  # python < 3.3
    from mock import Mock

from azure.identity._authn_client import AuthnClientBase


def test_auth_url_caching():
    first_access_token = "first-access-token"
    token_payload = {
        "access_token": first_access_token,
        "expires_in": 3600,
        "ext_expires_in": 3600,
        "token_type": "Bearer",
    }
    scopes = ["scope"]

    first_url = "https://first.com/segment"
    client = AuthnClientBase(first_url)

    # cache a token response
    response = Mock(context={"deserialized_data": token_payload}, http_request=HttpRequest("GET", first_url))
    client._deserialize_and_cache_token(response, scopes)

    # cache a response for the same scope from a different authority
    second_url = "https://second.com/segment"
    second_access_token = "second-access-token"
    token_payload["access_token"] = second_access_token
    response.http_request = HttpRequest("GET", second_url)
    client._deserialize_and_cache_token(response, scopes)

    # the cache should consider the authority
    assert client.get_cached_token(scopes, first_url) == first_access_token
    assert client.get_cached_token(scopes, second_url) == second_access_token
