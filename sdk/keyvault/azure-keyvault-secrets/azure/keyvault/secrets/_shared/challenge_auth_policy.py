# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
"""Policy implementing Key Vault's challenge authentication protocol.

Normally the protocol is only used for the client's first service request, upon which:
1. The challenge authentication policy sends a copy of the request, without authorization or content.
2. Key Vault responds 401 with a header (the 'challenge') detailing how the client should authenticate such a request.
3. The policy authenticates according to the challenge and sends the original request with authorization.

The policy caches the challenge and thus knows how to authenticate future requests. However, authentication
requirements can change. For example, a vault may move to a new tenant. In such a case the policy will attempt the
protocol again.
"""

import copy
import time

from azure.core.pipeline import PipelineContext, PipelineRequest
from azure.core.pipeline.policies import BearerTokenCredentialPolicy
from azure.core.pipeline.transport import HttpRequest

from .http_challenge import HttpChallenge
from . import http_challenge_cache as ChallengeCache

try:
    from typing import TYPE_CHECKING
except ImportError:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    from typing import Any, Dict, Optional
    from azure.core.credentials import AccessToken, TokenCredential
    from azure.core.pipeline.transport import HttpResponse


def _enforce_tls(request):
    # type: (PipelineRequest) -> None
    if not request.http_request.url.lower().startswith("https"):
        raise ServiceRequestError(
            "Bearer token authentication is not permitted for non-TLS protected (non-https) URLs."
        )


def _get_challenge_request(request):
    # type: (PipelineRequest) -> PipelineRequest

    # The challenge request is intended to provoke an authentication challenge from Key Vault, to learn how the
    # service request should be authenticated. It should be identical to the service request but with no body.
    challenge_request = HttpRequest(
        request.http_request.method, request.http_request.url, headers=request.http_request.headers
    )
    challenge_request.headers["Content-Length"] = "0"

    options = copy.deepcopy(request.context.options)
    context = PipelineContext(request.context.transport, **options)

    return PipelineRequest(http_request=challenge_request, context=context)


def _update_challenge(request, challenger):
    # type: (HttpRequest, HttpResponse) -> HttpChallenge
    """parse challenge from challenger, cache it, return it"""

    challenge = HttpChallenge(
        request.http_request.url,
        challenger.http_response.headers.get("WWW-Authenticate"),
        response_headers=challenger.http_response.headers,
    )
    ChallengeCache.set_challenge_for_url(request.http_request.url, challenge)
    return challenge


class ChallengeAuthPolicyBase(object):
    """Sans I/O base for challenge authentication policies"""

    def __init__(self, **kwargs):
        self._token = None  # type: Optional[AccessToken]
        super(ChallengeAuthPolicyBase, self).__init__(**kwargs)

    @property
    def _need_new_token(self):
        # type: () -> bool
        return not self._token or self._token.expires_on - time.time() < 300


class ChallengeAuthPolicy(BearerTokenCredentialPolicy):
    """policy for handling HTTP authentication challenges"""

    def on_before_request(self, request):
        # type: (PipelineRequest) -> None
        if self._scopes:
            super(ChallengeAuthPolicy, self).on_before_request(request)
        elif request.http_request.body:
            # discover the correct scope by eliciting an authentication challenge from Key Vault
            request.context["original_data"] = request.http_request.body
            request.http_request.set_json_body(None)
            request.http_request.headers["Content-Length"] = "0"

    def on_challenge(self, request, www_authenticate):
        # type: (PipelineRequest, str) -> bool
        try:
            challenge = HttpChallenge(request.http_request.url, www_authenticate)
            scope = challenge.get_scope() or challenge.get_resource() + "/.default"
            self._scopes = (scope,)
        except ValueError:
            # maybe super can handle this unexpected challenge
            return super(ChallengeAuthPolicy, self).on_challenge(request, www_authenticate)

        text = request.context.pop("original_data", None)
        request.http_request.set_text_body(text)  # no-op when text is None

        self._token = self._credential.get_token(*self._scopes)
        request.http_request.headers["Authorization"] = "Bearer " + self._token.token
        return True
