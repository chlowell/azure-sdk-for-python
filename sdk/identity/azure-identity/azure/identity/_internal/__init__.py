# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import os

from .._constants import EnvironmentVariables, KnownAuthorities


def get_default_authority():
    return os.environ.get(EnvironmentVariables.AZURE_AUTHORITY_HOST, KnownAuthorities.AZURE_PUBLIC_CLOUD)


# pylint:disable=wrong-import-position
from .aad_client import AadClient
from .aad_client_base import AadClientBase
from .auth_code_redirect_handler import AuthCodeRedirectServer
from .exception_wrapper import wrap_exceptions
from .msal_credentials import ConfidentialClientCredential, InteractiveCredential, PublicClientCredential
from .msal_transport_adapter import MsalTransportAdapter, MsalTransportResponse


def _scopes_to_resource(*scopes):
    """Convert an AADv2 scope to an AADv1 resource"""

    if len(scopes) != 1:
        raise ValueError("This credential requires exactly one scope per token request.")

    resource = scopes[0]
    if resource.endswith("/.default"):
        resource = resource[: -len("/.default")]

    return resource


__all__ = [
    "_scopes_to_resource",
    "AadClient",
    "AadClientBase",
    "AuthCodeRedirectServer",
    "ConfidentialClientCredential",
    "get_default_authority",
    "InteractiveCredential",
    "MsalTransportAdapter",
    "MsalTransportResponse",
    "PublicClientCredential",
    "wrap_exceptions",
]
