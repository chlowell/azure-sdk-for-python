# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import json
import time

try:
    from unittest import mock
except ImportError:  # python < 3.3
    import mock  # type: ignore

from azure.core.exceptions import ClientAuthenticationError

import pytest
from azure.core.credentials import AccessToken
from azure.identity import ManagedIdentityCredential, CredentialUnavailableError
from azure.identity._constants import Endpoints, EnvironmentVariables
from azure.identity._internal.user_agent import USER_AGENT
from azure.identity._internal.managed_identity_client_base import IMDS_RETRY_SETTINGS

from helpers import validating_transport, mock_response, Request

MANAGED_IDENTITY_ENVIRON = "azure.identity._credentials.managed_identity.os.environ"


def test_cloud_shell():
    """Cloud Shell environment: only MSI_ENDPOINT set"""

    access_token = "****"
    expires_on = 42
    expected_token = AccessToken(access_token, expires_on)
    endpoint = "http://localhost:42/token"
    scope = "scope"
    transport = validating_transport(
        requests=[
            Request(
                base_url=endpoint,
                method="POST",
                required_headers={"Metadata": "true", "User-Agent": USER_AGENT},
                required_data={"resource": scope},
            )
        ],
        responses=[
            mock_response(
                json_payload={
                    "access_token": access_token,
                    "expires_in": 0,
                    "expires_on": expires_on,
                    "not_before": int(time.time()),
                    "resource": scope,
                    "token_type": "Bearer",
                }
            )
        ],
    )

    with mock.patch("os.environ", {EnvironmentVariables.MSI_ENDPOINT: endpoint}):
        token = ManagedIdentityCredential(transport=transport).get_token(scope)
        assert token == expected_token


def test_cloud_shell_user_assigned_identity():
    """Cloud Shell environment: only MSI_ENDPOINT set"""

    access_token = "****"
    expires_on = 42
    client_id = "some-guid"
    expected_token = AccessToken(access_token, expires_on)
    endpoint = "http://localhost:42/token"
    scope = "scope"
    transport = validating_transport(
        requests=[
            Request(
                base_url=endpoint,
                method="POST",
                required_headers={"Metadata": "true", "User-Agent": USER_AGENT},
                required_data={"client_id": client_id, "resource": scope},
            )
        ],
        responses=[
            mock_response(
                json_payload={
                    "access_token": access_token,
                    "expires_in": 0,
                    "expires_on": expires_on,
                    "not_before": int(time.time()),
                    "resource": scope,
                    "token_type": "Bearer",
                }
            )
        ],
    )

    with mock.patch("os.environ", {EnvironmentVariables.MSI_ENDPOINT: endpoint}):
        token = ManagedIdentityCredential(client_id=client_id, transport=transport).get_token(scope)
        assert token == expected_token


def test_app_service():
    """App Service environment: MSI_ENDPOINT, MSI_SECRET set"""

    access_token = "****"
    expires_on = 42
    expected_token = AccessToken(access_token, expires_on)
    endpoint = "http://localhost:42/token"
    secret = "expected-secret"
    scope = "scope"
    transport = validating_transport(
        requests=[
            Request(
                base_url=endpoint,
                method="GET",
                required_headers={"secret": secret, "User-Agent": USER_AGENT},
                required_params={"api-version": "2017-09-01", "resource": scope},
            )
        ],
        responses=[
            mock_response(
                json_payload={
                    "access_token": access_token,
                    "expires_on": expires_on,
                    "resource": scope,
                    "token_type": "Bearer",
                }
            )
        ],
    )

    with mock.patch(
        "os.environ", {EnvironmentVariables.MSI_ENDPOINT: endpoint, EnvironmentVariables.MSI_SECRET: secret}
    ):
        token = ManagedIdentityCredential(transport=transport).get_token(scope)
        assert token == expected_token


def test_app_service_2017_09_01():
    """test parsing of App Service MSI 2017-09-01's eccentric platform-dependent expires_on strings"""

    access_token = "****"
    expires_on = 42
    expected_token = AccessToken(access_token, expires_on)
    url = "http://localhost:42/token"
    secret = "expected-secret"
    scope = "scope"

    transport = validating_transport(
        requests=[
            Request(
                url,
                method="GET",
                required_headers={"secret": secret, "User-Agent": USER_AGENT},
                required_params={"api-version": "2017-09-01", "resource": scope},
            )
        ]
        * 2,
        responses=[
            mock_response(
                json_payload={
                    "access_token": access_token,
                    "expires_on": "01/01/1970 00:00:{} +00:00".format(expires_on),  # linux format
                    "resource": scope,
                    "token_type": "Bearer",
                }
            ),
            mock_response(
                json_payload={
                    "access_token": access_token,
                    "expires_on": "1/1/1970 12:00:{} AM +00:00".format(expires_on),  # windows format
                    "resource": scope,
                    "token_type": "Bearer",
                }
            ),
        ],
    )

    with mock.patch.dict(
        MANAGED_IDENTITY_ENVIRON,
        {EnvironmentVariables.MSI_ENDPOINT: url, EnvironmentVariables.MSI_SECRET: secret},
        clear=True,
    ):
        token = ManagedIdentityCredential(transport=transport).get_token(scope)
        assert token == expected_token
        assert token.expires_on == expires_on

        token = ManagedIdentityCredential(transport=transport).get_token(scope)
        assert token == expected_token
        assert token.expires_on == expires_on


def test_app_service_user_assigned_identity():
    """App Service environment: MSI_ENDPOINT, MSI_SECRET set"""

    access_token = "****"
    expires_on = 42
    client_id = "some-guid"
    expected_token = AccessToken(access_token, expires_on)
    endpoint = "http://localhost:42/token"
    secret = "expected-secret"
    scope = "scope"
    transport = validating_transport(
        requests=[
            Request(
                base_url=endpoint,
                method="GET",
                required_headers={"secret": secret, "User-Agent": USER_AGENT},
                required_params={"api-version": "2017-09-01", "clientid": client_id, "resource": scope},
            )
        ],
        responses=[
            mock_response(
                json_payload={
                    "access_token": access_token,
                    "expires_on": expires_on,
                    "resource": scope,
                    "token_type": "Bearer",
                }
            )
        ],
    )

    with mock.patch(
        "os.environ", {EnvironmentVariables.MSI_ENDPOINT: endpoint, EnvironmentVariables.MSI_SECRET: secret}
    ):
        token = ManagedIdentityCredential(client_id=client_id, transport=transport).get_token(scope)
        assert token == expected_token


def test_imds():
    access_token = "****"
    expires_on = 42
    expected_token = AccessToken(access_token, expires_on)
    scope = "scope"
    transport = validating_transport(
        requests=[
            Request(url=Endpoints.IMDS),  # first request should be availability probe => match only the URL
            Request(
                base_url=Endpoints.IMDS,
                method="GET",
                required_headers={"Metadata": "true", "User-Agent": USER_AGENT},
                required_params={"api-version": "2018-02-01", "resource": scope},
            ),
        ],
        responses=[
            # probe receives error response
            mock_response(status_code=400, json_payload={"error": "this is an error message"}),
            mock_response(
                json_payload={
                    "access_token": access_token,
                    "expires_in": 42,
                    "expires_on": expires_on,
                    "ext_expires_in": 42,
                    "not_before": int(time.time()),
                    "resource": scope,
                    "token_type": "Bearer",
                }
            ),
        ],
    )

    # ensure e.g. $MSI_ENDPOINT isn't set, so we get ManagedIdentityCredential
    with mock.patch.dict("os.environ", clear=True):
        token = ManagedIdentityCredential(transport=transport).get_token(scope)
    assert token == expected_token


def test_imds_user_assigned_identity():
    access_token = "****"
    expires_on = 42
    expected_token = AccessToken(access_token, expires_on)
    endpoint = Endpoints.IMDS
    scope = "scope"
    client_id = "some-guid"
    transport = validating_transport(
        requests=[
            Request(base_url=endpoint),  # first request should be availability probe => match only the URL
            Request(
                base_url=endpoint,
                method="GET",
                required_headers={"Metadata": "true", "User-Agent": USER_AGENT},
                required_params={"api-version": "2018-02-01", "client_id": client_id, "resource": scope},
            ),
        ],
        responses=[
            # probe receives error response
            mock_response(status_code=400, json_payload={"error": "this is an error message"}),
            mock_response(
                json_payload={
                    "access_token": access_token,
                    "client_id": client_id,
                    "expires_in": 42,
                    "expires_on": expires_on,
                    "ext_expires_in": 42,
                    "not_before": int(time.time()),
                    "resource": scope,
                    "token_type": "Bearer",
                }
            ),
        ],
    )

    # ensure e.g. $MSI_ENDPOINT isn't set, so we get ManagedIdentityCredential
    with mock.patch.dict("os.environ", clear=True):
        token = ManagedIdentityCredential(client_id=client_id, transport=transport).get_token(scope)
    assert token == expected_token


def test_no_scopes():
    """The credential should raise ValueError when get_token is called with no scopes"""

    with mock.patch("os.environ", {EnvironmentVariables.MSI_ENDPOINT: "https://url"}):
        credential = ManagedIdentityCredential()

    with pytest.raises(ValueError):
        credential.get_token()


def test_multiple_scopes():
    """The credential should raise ValueError when get_token is called with more than one scope"""

    with mock.patch("os.environ", {EnvironmentVariables.MSI_ENDPOINT: "https://url"}):
        credential = ManagedIdentityCredential()

    with pytest.raises(ValueError):
        credential.get_token("one scope", "and another")


def test_identity_config_app_service():
    param_name, param_value = "foo", "bar"
    access_token = "****"
    expires_on = 42
    expected_token = AccessToken(access_token, expires_on)
    endpoint = "http://localhost:42/token"
    secret = "expected-secret"
    scope = "scope"

    transport = validating_transport(
        requests=[
            Request(
                base_url=endpoint,
                method="GET",
                required_headers={"secret": secret, "User-Agent": USER_AGENT},
                required_params={"api-version": "2017-09-01", "resource": scope, param_name: param_value,},
            )
        ],
        responses=[
            mock_response(
                json_payload={
                    "access_token": access_token,
                    "expires_on": expires_on,
                    "resource": scope,
                    "token_type": "Bearer",
                }
            )
        ],
    )

    with mock.patch.dict(
        ManagedIdentityCredential.__module__ + ".os.environ",
        {EnvironmentVariables.MSI_ENDPOINT: endpoint, EnvironmentVariables.MSI_SECRET: secret},
        clear=True,
    ):
        credential = ManagedIdentityCredential(identity_config={param_name: param_value}, transport=transport)
        token = credential.get_token(scope)

    assert token == expected_token


def test_identity_config_cloud_shell():
    param_name, param_value = "foo", "bar"
    access_token = "****"
    expires_on = 42
    expected_token = AccessToken(access_token, expires_on)
    endpoint = "http://localhost:42/token"
    scope = "scope"
    transport = validating_transport(
        requests=[
            Request(
                base_url=endpoint,
                method="POST",
                required_headers={"Metadata": "true", "User-Agent": USER_AGENT},
                required_data={"resource": scope, param_name: param_value},
            )
        ],
        responses=[
            mock_response(
                json_payload={
                    "access_token": access_token,
                    "expires_in": 0,
                    "expires_on": expires_on,
                    "not_before": int(time.time()),
                    "resource": scope,
                    "token_type": "Bearer",
                }
            )
        ],
    )

    with mock.patch.dict(
        ManagedIdentityCredential.__module__ + ".os.environ", {EnvironmentVariables.MSI_ENDPOINT: endpoint}, clear=True
    ):
        credential = ManagedIdentityCredential(identity_config={param_name: param_value}, transport=transport)
        token = credential.get_token(scope)

    assert token == expected_token


def test_imds_identity_not_available():
    """The credential should raise CredentialUnavailableError when IMDS responds 400 to a token request"""

    # first request is a probe, second a token request
    transport = validating_transport(
        requests=[Request()] * 2, responses=[mock_response(status_code=400, json_payload={})] * 2
    )

    credential = ManagedIdentityCredential(transport=transport)

    with pytest.raises(CredentialUnavailableError):
        credential.get_token("scope")


def test_unexpected_error():
    """The credential should raise ClientAuthenticationError when the endpoint returns an unexpected error"""

    error_message = "something went wrong"

    for code in range(401, 600):

        def send(request, **_):
            if "resource" not in request.query:
                # availability probe
                return mock_response(status_code=400, json_payload={})
            return mock_response(status_code=code, json_payload={"error": error_message})

        credential = ManagedIdentityCredential(transport=mock.Mock(send=send))

        with pytest.raises(ClientAuthenticationError) as ex:
            credential.get_token("scope")

        assert error_message in ex.value.message


def test_imds_retries():
    mock_response = mock.Mock(
        text=lambda encoding=None: b"{}",
        headers={"content-type": "application/json", "Retry-After": "0"},
        content_type="application/json",
    )
    mock_send = mock.Mock(return_value=mock_response)

    for status_code in (404, 429, 500):
        mock_send.reset_mock()
        mock_response.status_code = status_code
        try:
            ManagedIdentityCredential(transport=mock.Mock(send=mock_send)).get_token("scope")
        except ClientAuthenticationError:
            pass
        # first call was availability probe, second the original request;
        # credential should then have retried until reaching the expected retry total
        assert mock_send.call_count == 2 + IMDS_RETRY_SETTINGS["retry_total"]


def test_cache():
    scope = "https://foo.bar"
    expired = "this token's expired"
    now = int(time.time())
    token_payload = {
        "access_token": expired,
        "refresh_token": "",
        "expires_in": 0,
        "expires_on": now - 300,  # expired 5 minutes ago
        "not_before": now,
        "resource": scope,
        "token_type": "Bearer",
    }

    mock_response = mock.Mock(
        text=lambda encoding=None: json.dumps(token_payload),
        headers={"content-type": "application/json"},
        status_code=200,
        content_type="application/json",
    )
    mock_send = mock.Mock(return_value=mock_response)

    credential = ManagedIdentityCredential(transport=mock.Mock(send=mock_send))
    token = credential.get_token(scope)
    assert token.token == expired
    assert mock_send.call_count == 2  # first request was probing for endpoint availability

    # calling get_token again should provoke another HTTP request
    good_for_an_hour = "this token's good for an hour"
    token_payload["expires_on"] = int(time.time()) + 3600
    token_payload["expires_in"] = 3600
    token_payload["access_token"] = good_for_an_hour
    token = credential.get_token(scope)
    assert token.token == good_for_an_hour
    assert mock_send.call_count == 3

    # get_token should return the cached token now
    token = credential.get_token(scope)
    assert token.token == good_for_an_hour
    assert mock_send.call_count == 3


def test_identity_config_imds():
    param_name, param_value = "foo", "bar"
    access_token = "****"
    expires_on = 42
    expected_token = AccessToken(access_token, expires_on)
    scope = "scope"
    transport = validating_transport(
        requests=[
            Request(base_url=Endpoints.IMDS),
            Request(
                base_url=Endpoints.IMDS,
                method="GET",
                required_headers={"Metadata": "true", "User-Agent": USER_AGENT},
                required_params={"api-version": "2018-02-01", "resource": scope, param_name: param_value},
            ),
        ],
        responses=[
            mock_response(status_code=400, json_payload={"error": "this is an error message"}),
            mock_response(
                json_payload={
                    "access_token": access_token,
                    "expires_in": 42,
                    "expires_on": expires_on,
                    "ext_expires_in": 42,
                    "not_before": int(time.time()),
                    "resource": scope,
                    "token_type": "Bearer",
                }
            ),
        ],
    )

    credential = ManagedIdentityCredential(identity_config={param_name: param_value}, transport=transport)
    token = credential.get_token(scope)

    assert token == expected_token
