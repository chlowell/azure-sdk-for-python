# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import abc
import base64
import copy
import json
import time
from uuid import uuid4

import six
from msal import TokenCache

from azure.core.pipeline.transport import HttpRequest
from azure.core.credentials import AccessToken
from azure.core.exceptions import ClientAuthenticationError
from . import get_default_authority, normalize_authority

try:
    from typing import TYPE_CHECKING
except ImportError:
    TYPE_CHECKING = False

try:
    ABC = abc.ABC
except AttributeError:  # Python 2.7, abc exists, but not ABC
    ABC = abc.ABCMeta("ABC", (object,), {"__slots__": ()})  # type: ignore

if TYPE_CHECKING:
    # pylint:disable=unused-import,ungrouped-imports
    from typing import Any, Optional, Sequence, Union
    from azure.core.pipeline import AsyncPipeline, Pipeline
    from azure.core.pipeline.policies import AsyncHTTPPolicy, HTTPPolicy, SansIOHTTPPolicy
    from azure.core.pipeline.transport import AsyncHttpTransport, HttpTransport
    from .._internal import AadClientCertificate

    PipelineType = Union[AsyncPipeline, Pipeline]
    PolicyType = Union[AsyncHTTPPolicy, HTTPPolicy, SansIOHTTPPolicy]
    TransportType = Union[AsyncHttpTransport, HttpTransport]


class AadClientBase(ABC):
    def __init__(self, tenant_id, client_id, authority=None, cache=None, **kwargs):
        # type: (str, str, Optional[str], Optional[TokenCache], **Any) -> None
        authority = normalize_authority(authority) if authority else get_default_authority()
        self._token_endpoint = "/".join((authority, tenant_id, "oauth2/v2.0/token"))
        self._cache = cache or TokenCache()
        self._client_id = client_id
        self._pipeline = self._build_pipeline(**kwargs)

    def get_cached_access_token(self, scopes):
        # type: (Sequence[str]) -> Optional[AccessToken]
        tokens = self._cache.find(TokenCache.CredentialType.ACCESS_TOKEN, target=list(scopes))
        for token in tokens:
            expires_on = int(token["expires_on"])
            if expires_on - 300 > int(time.time()):
                return AccessToken(token["secret"], expires_on)
        return None

    def get_cached_refresh_tokens(self, scopes):
        # type: (Sequence[str]) -> Sequence[dict]
        """Assumes all cached refresh tokens belong to the same user"""
        return self._cache.find(TokenCache.CredentialType.REFRESH_TOKEN, target=list(scopes))

    @abc.abstractmethod
    def obtain_token_by_authorization_code(self, scopes, code, redirect_uri, client_secret=None, **kwargs):
        pass

    @abc.abstractmethod
    def obtain_token_by_client_certificate(self, scopes, certificate, **kwargs):
        pass

    @abc.abstractmethod
    def obtain_token_by_client_secret(self, scopes, secret, **kwargs):
        pass

    @abc.abstractmethod
    def obtain_token_by_refresh_token(self, scopes, refresh_token, **kwargs):
        pass

    @abc.abstractmethod
    def _build_pipeline(self, config=None, policies=None, transport=None, **kwargs):
        pass

    def _process_response(self, response, scopes, now):
        # type: (dict, Sequence[str], int) -> AccessToken
        _raise_for_error(response)

        # TokenCache.add mutates the response. In particular, it removes tokens.
        response_copy = copy.deepcopy(response)

        self._cache.add(event={"response": response, "scope": scopes, "client_id": self._client_id}, now=now)
        if "expires_on" in response_copy:
            expires_on = int(response_copy["expires_on"])
        elif "expires_in" in response_copy:
            expires_on = now + int(response_copy["expires_in"])
        else:
            _scrub_secrets(response_copy)
            raise ClientAuthenticationError(
                message="Unexpected response from Azure Active Directory: {}".format(response_copy)
            )
        return AccessToken(response_copy["access_token"], expires_on)

    def _get_auth_code_request(self, scopes, code, redirect_uri, client_secret=None):
        # type: (Sequence[str], str, str, Optional[str]) -> HttpRequest
        data = {
            "client_id": self._client_id,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
        }
        if client_secret:
            data["client_secret"] = client_secret

        request = HttpRequest(
            "POST", self._token_endpoint, headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        request.set_formdata_body(data)
        return request

    def _get_client_certificate_request(self, scopes, certificate):
        # type: (Sequence[str], AadClientCertificate) -> HttpRequest
        assertion = self._get_jwt_assertion(certificate)
        data = {
            "client_assertion": assertion,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_id": self._client_id,
            "grant_type": "client_credentials",
            "scope": " ".join(scopes),
        }

        request = HttpRequest(
            "POST", self._token_endpoint, headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        request.set_formdata_body(data)
        return request

    def _get_jwt_assertion(self, certificate):
        # type: (AadClientCertificate) -> str
        now = int(time.time())
        header = six.ensure_binary(
            json.dumps({"typ": "JWT", "alg": "RS256", "x5t": certificate.thumbprint}), encoding="utf-8"
        )
        payload = six.ensure_binary(
            json.dumps(
                {
                    "jti": str(uuid4()),
                    "aud": self._token_endpoint,
                    "iss": self._client_id,
                    "sub": self._client_id,
                    "nbf": now,
                    "exp": now + (60 * 30),
                }
            ),
            encoding="utf-8",
        )
        jws = base64.urlsafe_b64encode(header) + b"." + base64.urlsafe_b64encode(payload)
        signature = certificate.sign(jws)
        jwt_bytes = jws + b"." + base64.urlsafe_b64encode(signature)

        return jwt_bytes.decode("utf-8")

    def _get_client_secret_request(self, scopes, secret):
        # type: (Sequence[str], str) -> HttpRequest
        data = {
            "client_id": self._client_id,
            "client_secret": secret,
            "grant_type": "client_credentials",
            "scope": " ".join(scopes),
        }
        request = HttpRequest(
            "POST", self._token_endpoint, headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        request.set_formdata_body(data)
        return request

    def _get_refresh_token_request(self, scopes, refresh_token):
        # type: (Sequence[str], str) -> HttpRequest
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": " ".join(scopes),
            "client_id": self._client_id,
        }
        request = HttpRequest(
            "POST", self._token_endpoint, headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        request.set_formdata_body(data)
        return request


def _scrub_secrets(response):
    # type: (dict) -> None
    for secret in ("access_token", "refresh_token"):
        if secret in response:
            response[secret] = "***"


def _raise_for_error(response):
    # type: (dict) -> None
    if "error" not in response:
        return

    _scrub_secrets(response)
    if "error_description" in response:
        message = "Azure Active Directory error '({}) {}'".format(response["error"], response["error_description"])
    else:
        message = "Azure Active Directory error '{}'".format(response)
    raise ClientAuthenticationError(message=message)
