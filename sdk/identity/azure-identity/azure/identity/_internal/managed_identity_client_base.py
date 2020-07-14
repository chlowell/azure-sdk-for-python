# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import abc
import calendar
from enum import Enum
import os
import time
from typing import TYPE_CHECKING

from msal import TokenCache
from azure.core.exceptions import ClientAuthenticationError
from azure.core.pipeline.policies import ContentDecodePolicy
from azure.core.pipeline.transport import HttpRequest, HttpResponse
from .._constants import EnvironmentVariables, Endpoints

if TYPE_CHECKING:
    # pylint:disable=unused-import;ungrouped-imports
    from typing import Any, Optional, Union
    from azure.core.credentials import AccessToken

try:
    ABC = abc.ABC
except AttributeError:  # Python 2.7
    ABC = abc.ABCMeta("ABC", (object,), {"__slots__": ()})  # type: ignore

# given RetryPolicy's implementation, these settings most closely match the guidance at
# https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/how-to-use-vm-token#retry-guidance
IMDS_RETRY_SETTINGS = {
    "retry_total": 5,
    "retry_status": 5,
    "retry_backoff_factor": 4,
    "retry_backoff_max": 60,
    "retry_on_status_codes": [404, 429] + list(range(500, 600)),
}


class ManagedIdentityType(Enum):
    app_service_2017 = 0
    app_service_2019 = 1
    cloud_shell = 2
    IMDS = 3
    unavailable = 4
    unknown = 5


class ManagedIdentityClientBase(ABC):
    def __init__(self, client_id=None, **kwargs):
        # type: (Optional[str], **Any) -> None
        if EnvironmentVariables.IDENTITY_ENDPOINT in os.environ:
            if EnvironmentVariables.IDENTITY_HEADER in os.environ:
                self._get_request = self._get_app_service_2019_request
                self._type = ManagedIdentityType.app_service_2019
            else:
                self._type = ManagedIdentityType.unavailable  # TODO: Azure Arc

        elif EnvironmentVariables.MSI_ENDPOINT in os.environ:
            if EnvironmentVariables.MSI_SECRET in os.environ:
                self._get_request = self._get_app_service_2017_request
                self._type = ManagedIdentityType.app_service_2017
            else:
                self._get_request = self._get_cloud_shell_request
                self._type = ManagedIdentityType.cloud_shell

        else:
            kwargs.update(IMDS_RETRY_SETTINGS)
            self._get_request = self._get_imds_request
            self._type = ManagedIdentityType.unknown

        self._cache = kwargs.pop("_cache", None) or TokenCache()
        self._identity_config = kwargs.pop("identity_config", None) or {}
        if client_id:
            if self._identity_config:
                raise ValueError('"client_id" and "identity_config" are mutually exclusive')
            if self._type == ManagedIdentityType.app_service_2017:
                self._identity_config["clientid"] = client_id
            else:
                self._identity_config["client_id"] = client_id

        self._pipeline = self._build_pipeline(**kwargs)

    @abc.abstractmethod
    def _probe_imds(self):
        # type: () -> None
        pass

    @abc.abstractmethod
    def request_token(self, scope):
        # type: (str) -> AccessToken
        pass

    def get_cached_access_token(self, scope):
        # type: (str) -> Optional[AccessToken]
        tokens = self._cache.find(TokenCache.CredentialType.ACCESS_TOKEN, target=[scope])
        for token in tokens:
            expires_on = int(token["expires_on"])
            if expires_on - 300 > int(time.time()):
                return AccessToken(token["secret"], expires_on)
        return None

    def _get_app_service_2017_request(self, scope):
        # type: (str) -> HttpRequest
        url = os.environ[EnvironmentVariables.MSI_ENDPOINT]
        request = HttpRequest("GET", url, headers={"secret": os.environ[EnvironmentVariables.MSI_SECRET]})
        request.format_parameters(dict({"api-version": "2017-09-01", "resource": scope}, **self._identity_config))
        return request

    def _get_app_service_2019_request(self, scope):
        # type: (str) -> HttpRequest
        url = os.environ[EnvironmentVariables.IDENTITY_ENDPOINT]
        request = HttpRequest(
            "GET", url, headers={"X-IDENTITY-HEADER": os.environ[EnvironmentVariables.IDENTITY_HEADER]}
        )
        request.format_parameters(dict({"api-version": "2019-08-01", "resource": scope}, **self._identity_config))
        return request

    def _get_cloud_shell_request(self, scope):
        # type: (str) -> HttpRequest
        url = os.environ[EnvironmentVariables.MSI_ENDPOINT]
        data = dict({"resource": scope}, **self._identity_config)
        return HttpRequest("POST", url, headers={"Metadata": "true"}, data=data)

    def _get_imds_request(self, scope):
        # type: (str) -> HttpRequest
        request = HttpRequest("GET", Endpoints.IMDS, headers={"Metadata": "true"})
        request.format_parameters(dict({"api-version": "2018-02-01", "resource": scope}, **self._identity_config))
        return request

    def _process_response(self, response, request_time):
        # type: (HttpResponse, int) -> AccessToken
        content = ContentDecodePolicy.deserialize_from_http_generics(response)
        if not content or "access_token" not in content or not ("expires_in" in content or "expires_on" in content):
            if content and "access_token" in content:
                content["access_token"] = "****"
            raise ClientAuthenticationError(message='Unexpected response "{}"'.format(content), response=response)

        expires_on = content.get("expires_on") or int(content["expires_in"]) + request_time  # type: Union[str, int]
        if self._type == ManagedIdentityType.app_service_2017:
            t = _parse_app_service_expires_on(expires_on)  # type: ignore
            expires_on = calendar.timegm(t)

        # now we have an int expires_on, ensure the cache entry gets it
        content["expires_on"] = expires_on

        token = AccessToken(content["access_token"], expires_on)

        # caching is the final step because "add" mutates "content"
        self._cache.add(
            event={"response": content, "scope": [content["resource"]]}, now=request_time,
        )

        return token


def _parse_app_service_expires_on(expires_on):
    # type: (str) -> time.struct_time
    """Parse an App Service MSI version 2017-09-01 expires_on value to struct_time.

    This version of the API returns expires_on as a UTC datetime string rather than epoch seconds. The string's
    format depends on the OS. Responses on Windows include AM/PM, for example "1/16/2020 5:24:12 AM +00:00".
    Responses on Linux do not, for example "06/20/2019 02:57:58 +00:00".

    :raises ValueError: ``expires_on`` didn't match an expected format
    """

    # parse the string minus the timezone offset
    if expires_on.endswith(" +00:00"):
        date_string = expires_on[: -len(" +00:00")]
        for format_string in ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p"):  # (Linux, Windows)
            try:
                return time.strptime(date_string, format_string)
            except ValueError:
                pass

    raise ValueError("'{}' doesn't match the expected format".format(expires_on))
