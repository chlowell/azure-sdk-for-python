# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import functools

try:
    from unittest.mock import Mock
except ImportError:  # python < 3.3
    from mock import Mock

from azure.core.credentials import AccessToken
from azure.identity import EnvironmentCredential
from devtools_testutils import AzureMgmtPreparer

from cached_preparer import cached_resource_test


class KeyVaultClientPreparer(AzureMgmtPreparer):
    def __init__(self, client_cls, name_prefix="vault", random_name_enabled=True, use_cache=False, **kwargs):
        super(KeyVaultClientPreparer, self).__init__(name_prefix, 24, random_name_enabled=random_name_enabled, **kwargs)
        self._client_cls = client_cls
        self.set_cache(use_cache)

    def create_credential(self):
        if self.is_live:
            return EnvironmentCredential()

        return Mock(get_token=lambda *_: AccessToken("fake-token", 0))

    def create_resource(self, _, **kwargs):
        credential = self.create_credential()
        client = self._client_cls(kwargs.get("vault_uri"), credential, **self.client_kwargs)
        return {"client": client}


def CachedKeyVaultClientPreparer(client_cls):
    return functools.partial(cached_resource_test, functools.partial(KeyVaultClientPreparer,client_cls))
