# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import abc
import calendar
import time
from enum import Enum
import os
from time import struct_time
from typing import TYPE_CHECKING, Union

from azure.core.credentials import AccessToken
from azure.core.exceptions import ClientAuthenticationError
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.policies import ContentDecodePolicy
from azure.core.pipeline.transport import HttpRequest
from azure.identity._constants import EnvironmentVariables, Endpoints

if TYPE_CHECKING:
    # pylint:disable=unused-import;ungrouped-imports
    from azure.core.credentials import AccessToken
    from azure.core.pipeline.transport import HttpResponse

try:
    ABC = abc.ABC
except AttributeError:  # Python 2.7, abc exists, but not ABC
    ABC = abc.ABCMeta("ABC", (object,), {"__slots__": ()})  # type: ignore


# given RetryPolicy's implementation, these settings most closely match the documented guidance for IMDS
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


class ManagedIdentityClientBase(ABC):
    def __init__(self, **kwargs):
        if EnvironmentVariables.IDENTITY_ENDPOINT in os.environ:
            if EnvironmentVariables.IDENTITY_HEADER in os.environ:
                self._get_request = self._get_app_service_2019_request
                self._identity_available = True
            else:
                self._identity_available = False  # TODO: hybrid

        elif EnvironmentVariables.MSI_ENDPOINT in os.environ:
            self._identity_available = True
            if EnvironmentVariables.MSI_SECRET in os.environ:
                self._get_request = self._get_app_service_2017_request
            else:
                self._get_request = self._get_cloud_shell_request

        else:
            self._identity_available = None

            # merge user provided retry settings with defaults, former overwriting the latter
            retry_settings = {key: kwargs.get(key, IMDS_RETRY_SETTINGS[key]) for key in IMDS_RETRY_SETTINGS}
            kwargs.update(retry_settings)
            self._get_request = self._get_imds_request

        self._pipeline = self._build_pipeline(**kwargs)

    @abc.abstractmethod
    def _probe_imds(self):
        pass

    @abc.abstractmethod
    def request_token(self, scope):
        # type: (str) -> AccessToken
        pass

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
        request = HttpRequest("GET", Endpoints.IMDS, headers={"secret": os.environ[EnvironmentVariables.MSI_SECRET]})
        request.format_parameters(dict({"api-version": "2018-02-01", "resource": scope}, **self._identity_config))
        return request

    def _process_response(self, response, request_time):
        # type: (PipelineResponse, int) -> AccessToken
        content = ContentDecodePolicy.deserialize_from_http_generics(response)
        if not content or "access_token" not in content or not ("expires_in" in content or "expires_on" in content):
            if content and "access_token" in content:
                content["access_token"] = "****"
            raise ClientAuthenticationError(message='Unexpected response "{}"'.format(content), response=response)

        expires_on = content.get("expires_on") or int(content["expires_in"]) + request_time  # type: Union[str, int]
        try:
            expires_on = int(expires_on)
        except ValueError:
            # probably an App Service MSI 2017-09-01 response, convert it to epoch seconds
            try:
                t = self._parse_app_service_expires_on(expires_on)  # type: ignore
                expires_on = calendar.timegm(t)
            except ValueError:
                # have a token but don't know when it expires -> treat it as single-use
                expires_on = request_time

        # now we have an int expires_on, ensure the cache entry gets it
        content["expires_on"] = expires_on

        token = AccessToken(content["access_token"], expires_on)

        # caching is the final step because 'add' mutates 'content'
        self._cache.add(
            event={"response": content, "scope": response.http_request.body["scope"].split()}, now=request_time,
        )

        return token


def _parse_app_service_expires_on(expires_on):
    # type: (str) -> struct_time
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
