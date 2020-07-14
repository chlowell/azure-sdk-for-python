# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
from azure.core.credentials import AccessToken
from .._internal import _scopes_to_resource
from .._internal.managed_identity_client import ManagedIdentityClient

try:
    from typing import TYPE_CHECKING
except ImportError:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    # pylint:disable=unused-import
    from typing import Any


class ManagedIdentityCredential(object):
    """Authenticates with an Azure managed identity in any hosting environment which supports managed identities.

    This credential defaults to using a system-assigned identity. To configure a user-assigned identity, use one of
    the keyword arguments.

    :keyword str client_id: a user-assigned identity's client ID. This is supported in all hosting environments.
    :keyword identity_config: a mapping ``{parameter_name: value}`` specifying a user-assigned identity by its object
      or resource ID, for example ``{"object_id": "..."}``. Check the documentation for your hosting environment to
      learn what values it expects.
    :paramtype identity_config: Mapping[str, str]
    """

    def __init__(self, **kwargs):
        # type: (**Any) -> None
        self._client = ManagedIdentityClient(**kwargs)

    def get_token(self, *scopes, **kwargs):  # pylint:disable=unused-argument
        # type: (*str, **Any) -> AccessToken
        """Request an access token for `scopes`.

        .. note:: This method is called by Azure SDK clients. It isn't intended for use in application code.

        :param str scopes: desired scope for the access token. This credential allows only one scope per request.
        :rtype: :class:`azure.core.credentials.AccessToken`
        :raises ~azure.identity.CredentialUnavailableError: managed identity isn't available in the hosting environment
        """
        scope = _scopes_to_resource(*scopes)
        return self._client.request_token(scope)
