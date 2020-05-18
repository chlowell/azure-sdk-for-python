# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import msal

from .persistent_cache import load_service_principal_cache


class ServicePrincipalCacheMixin(object):
    def __init__(self, client_id, enable_persistent_cache=False,allow_unencrypted_cache=False, **kwargs):
        if enable_persistent_cache:
            self._cache = load_service_principal_cache(allow_unencrypted_cache)
        else:
            self._cache = msal.TokenCache()
        super(ServicePrincipalCacheMixin, self).__init__()
