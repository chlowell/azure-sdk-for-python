# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import functools

from typing import TYPE_CHECKING
import msal

if TYPE_CHECKING:
    from typing import Any, Callable, Optional


class _CacheWrapper(msal.SerializableTokenCache):
    """Wrapper for in-memory token caches.

    This is required for this module's TokenCache class to override msal.SerializableTokenCache methods without
    exposing that class's attributes.
    """

    def __init__(self, update_callback=None):
        # type: (Optional[Callable]) -> None
        self._update_callback = update_callback or (lambda: None)
        super(_CacheWrapper, self).__init__()

    def modify(self, credential_type, old_entry, new_key_value_pairs=None):
        super(_CacheWrapper, self).modify(credential_type, old_entry, new_key_value_pairs)
        self._update_callback()


class TokenCache(object):
    """In memory token cache

    :keyword Callable[TokenCache, None] update_callback: called when the cache is updated
    """

    def __init__(self, **kwargs):
        # type: (**Any) -> None
        if "update_callback" in kwargs:
            # ensure _CacheWrapper has a reference to this TokenCache
            kwargs["update_callback"] = functools.partial(kwargs["update_callback"], self)
        self._cache = _CacheWrapper(**kwargs)


def serialize_token_cache(cache):
    # type: (TokenCache) -> bytes
    """Serialize the contents of a :class:`~azure.identity.TokenCache`

    :param cache: cache to serialize
    :type cache: ~azure.identity.TokenCache
    :return: bytes
    """
    return cache._cache.serialize().encode("utf-8")  # pylint:disable=protected-access


def deserialize_token_cache(data, **kwargs):
    # type: (bytes, **Any) -> TokenCache
    """Deserialize data into a new :class:`~azure.identity.TokenCache`

    :param bytes data: authentication data returned by :func:`~azure.identity.serialize_token_cache`
    :keyword Callable[TokenCache, None] update_callback: called when the cache is updated
    """
    cache = TokenCache(**kwargs)
    cache._cache.deserialize(data.decode("utf-8"))  # pylint:disable=protected-access
    return cache
