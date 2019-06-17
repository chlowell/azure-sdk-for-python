# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE.txt in the project root for
# license information.
# -------------------------------------------------------------------------
import threading
from typing import TYPE_CHECKING

from azure.core.pipeline.policies import HTTPPolicy
from azure.core.pipeline.policies.authentication import _BearerTokenCredentialPolicyBase

from .http_challenge import HttpChallenge
from . import http_challenge_cache as ChallengeCache

if TYPE_CHECKING:
    # pylint:disable=unused-import
    from azure.core.credentials import TokenCredential
    from azure.core.pipeline import PipelineRequest


class AuthChallengePolicy(_BearerTokenCredentialPolicyBase, HTTPPolicy):
    """policy for handling HTTP authentication challenges"""

    def __init__(self, credential, **kwargs):  # pylint:disable=unused-argument
        # type: (TokenCredential, Mapping[str, Any]) -> None
        super(AuthChallengePolicy, self).__init__(credential, **kwargs)
        self._challenges = {}  # type: Dict[str, HttpChallenge]
        self._lock = threading.Lock()

    def send(self, request):
        # type: (PipelineRequest) -> None

        challenge = ChallengeCache.get_challenge_for_url(request.url)
        # TODO: handle message security
        if challenge:
            pass
        else:
            self._handle_challenge(request)

        # response = self.next.send(request)
        # if response.http_response.status_code != 401:
        #     return response

        # try:
        #     challenge = HttpChallenge(
        #         request.http_request.url,
        #         response.http_response.headers.get("WWW-Authenticate"),
        #         response_headers=response.http_response.headers,
        #     )
        # except ValueError:
        #     # response is not a challenge -> no action for this policy
        #     return response

        # # TODO: PoP challenge
        # if not challenge.is_bearer_challenge():
        #     return response

        # # response is an auth challenge -> add parameters to context, send the request again
        # request.context["auth_url"] = challenge.get_authorization_server()
        # request.context["scope"] = challenge.get_resource()  # TODO: what's challenge's scope parameter for?

        return self.next.send(request)

    def _handle_challenge(self, request):
        # provoke a challenge by sending the request with no body
        original_body = request.body
        request.body = ""
        request.headers["Content-Length"] = 0

        self.next.send(request)