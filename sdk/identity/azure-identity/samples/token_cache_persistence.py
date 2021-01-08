# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
"""Demonstrates configuring and customizing token cache persistence.

Many credential implementations in azure-identity have an underlying TokenCache which holds sensitive authentication
data such as account information, access tokens, and refresh tokens. By default this is an in memory cache not shared
with other credential instance. Some applications need to share a token cache among credentials, and persist it across
executions. This file shows how to do this with the TokenCache and PeristentTokenCache classes.

IMPORTANT: token caches MUST be protected. Decisions regarding a cache's storage must consider that a breach of its
contents will fully compromise all accounts it contains.
"""

from azure.identity import InteractiveBrowserCredential, PersistentTokenCache

# PersistentTokenCache represents a persistent token cache managed by the Azure SDK. It defaults to
# the cache shared by Microsoft development applications (today, only Visual Studio) that
# SharedTokenCacheCredential also uses.
cache = PersistentTokenCache()
credential = InteractiveBrowserCredential(token_cache=cache)

# Applications preferring to isolate their authentication data from other applications can specify
# a name for their cache instance.
cache = PersistentTokenCache(name="my_application")
credential = InteractiveBrowserCredential(token_cache=cache)

# By default, PersistentTokenCache encrypts its data with the current platform's user data protection
# APIs, and will raise an error when it isn't able to do so. Applications can configure it to instead
# fall back to storing data in clear text.
cache = PersistentTokenCache(allow_unencrypted_storage=True)


# TokenCache caches authentication data in memory and optionally executes a callback when authentication
# data changes. With this callback and the deserialize_token_cache serialize_token_cache methods that
# enable serializing a TokenCache to/from bytes at any time, applications can implement their own
# persistence method.
#
# IMPORTANT: This code assumes the location of the file it uses for storage is secure. serialize_token_cache
#            returns unencrypted bytes. It's the responsibility of the application to protect this data.
from azure.identity import deserialize_token_cache, serialize_token_cache, TokenCache

CACHE_FILE = "sample_token_cache"

def on_update(cache: TokenCache) -> None:
    data = serialize_token_cache(cache)
    with open(CACHE_FILE, "wb") as f:
        f.write(data)

# deserializing cache data into a new in-memory cache instance
with open(CACHE_FILE, "rb") as f:
    data = f.read()

deserialized_cache = deserialize_token_cache(cache_bytes, update_callback=on_update)
credential = InteractiveBrowserCredential(token_cache=deserialized_cache)
