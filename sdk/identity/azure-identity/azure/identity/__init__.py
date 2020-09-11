# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
"""Credentials for Azure SDK clients."""

from ._auth_record import AuthenticationRecord
from ._exceptions import AuthenticationRequiredError, CredentialUnavailableError
from ._constants import AzureAuthorityHosts, KnownAuthorities
from ._credentials import (
    AzureCliCredential,
    AuthorizationCodeCredential,
    CertificateCredential,
    ChainedTokenCredential,
    ClientSecretCredential,
    DefaultAzureCredential,
    DeviceCodeCredential,
    EnvironmentCredential,
    InteractiveBrowserCredential,
    ManagedIdentityCredential,
    SharedTokenCacheCredential,
    UsernamePasswordCredential,
    VisualStudioCodeCredential,
)
from ._token_cache import deserialize_token_cache, serialize_token_cache, TokenCache
from ._internal.persistent_cache import PersistentTokenCache


__all__ = [
    "AuthenticationRecord",
    "AuthenticationRequiredError",
    "AuthorizationCodeCredential",
    "AzureAuthorityHosts",
    "AzureCliCredential",
    "CertificateCredential",
    "ChainedTokenCredential",
    "ClientSecretCredential",
    "CredentialUnavailableError",
    "DefaultAzureCredential",
    "deserialize_token_cache",
    "DeviceCodeCredential",
    "EnvironmentCredential",
    "InteractiveBrowserCredential",
    "KnownAuthorities",
    "ManagedIdentityCredential",
    "PersistentTokenCache",
    "serialize_token_cache",
    "SharedTokenCacheCredential",
    "TokenCache",
    "UsernamePasswordCredential",
    "VisualStudioCodeCredential",
]

from ._version import VERSION

__version__ = VERSION
