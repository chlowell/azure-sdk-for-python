# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import time
from typing import TYPE_CHECKING

import six
from azure.core.configuration import Configuration
from azure.core.exceptions import HttpResponseError, ClientAuthenticationError
from azure.core.pipeline import Pipeline
from azure.core.pipeline.policies import (
    RetryPolicy,
    DistributedTracingPolicy,
    HttpLoggingPolicy,
    NetworkTraceLoggingPolicy,
    UserAgentPolicy,
)
from azure.core.pipeline.transport import HttpRequest
from azure.identity import CredentialUnavailableError
from azure.identity._constants import Endpoints
from azure.identity._internal.user_agent import USER_AGENT

from .managed_identity_client_base import ManagedIdentityClientBase, ManagedIdentityType

if TYPE_CHECKING:
    # pylint:disable=unused-import;ungrouped-import
    from typing import Any, Optional
    from azure.core.credentials import AccessToken


class ManagedIdentityClient(ManagedIdentityClientBase):
    def request_token(self, scope):
        # type: (str) -> AccessToken
        if self._type is None:
            self._probe_imds()

        if self._type == ManagedIdentityType.unavailable:
            raise CredentialUnavailableError(
                "ManagedIdentityCredential authentication unavailable, no managed identity endpoint found."
            )

        token = self.get_cached_access_token(scope)
        if not token:
            request = self._get_request(scope)
            now = int(time.time())
            try:
                response = self._pipeline.run(request)
                token = self._process_response(response.http_response, now)
            except HttpResponseError as ex:
                if self._type == ManagedIdentityType.IMDS and ex.status_code == 400:
                    self._type = ManagedIdentityType.unavailable
                    message = "ManagedIdentityCredential authentication unavailable. "
                    if self._identity_config:
                        message += "The requested identity has not been assigned to this resource."
                    else:
                        message += "No identity has been assigned to this resource."
                    six.raise_from(CredentialUnavailableError(message=message, response=ex.response), ex)

                six.raise_from(ClientAuthenticationError(message=ex.message, response=ex.response), ex)

        return token

    def _probe_imds(self):
        """Send an invalid token request to learn whether the IMDS endpoint is available"""

        request = HttpRequest("GET", Endpoints.IMDS)
        try:
            self._pipeline.run(request, connection_timeout=0.3, retry_total=0)
            self._type = ManagedIdentityType.IMDS
        except HttpResponseError:
            # we consider any response to indicate the endpoint is available
            self._type = ManagedIdentityType.IMDS
        except Exception:  # pylint:disable=broad-except
            # if anything else was raised, assume the endpoint is unavailable
            self._type = ManagedIdentityType.unavailable

    # pylint:disable=no-self-use
    def _build_pipeline(self, config=None, policies=None, transport=None, **kwargs):
        # type: (Optional[Configuration], Optional[List[Policy]], Optional[HttpTransport], **Any) -> Pipeline
        config = config or _create_config(**kwargs)
        policies = policies or [
            config.user_agent_policy,
            config.retry_policy,
            config.logging_policy,
            DistributedTracingPolicy(**kwargs),
            HttpLoggingPolicy(**kwargs),
        ]
        if not transport:
            from azure.core.pipeline.transport import RequestsTransport

            transport = RequestsTransport(**kwargs)

        return Pipeline(transport=transport, policies=policies)


def _create_config(**kwargs):
    # type: (**Any) -> Configuration
    config = Configuration(**kwargs)
    config.logging_policy = NetworkTraceLoggingPolicy(**kwargs)
    config.retry_policy = RetryPolicy(**kwargs)
    config.user_agent_policy = UserAgentPolicy(base_user_agent=USER_AGENT, **kwargs)
    return config
