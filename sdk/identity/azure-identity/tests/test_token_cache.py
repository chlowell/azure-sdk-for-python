# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import json

try:
    from unittest.mock import Mock, patch
except ImportError:
    from mock import Mock, patch  # type: ignore


from azure.identity import deserialize_token_cache, PersistentTokenCache, serialize_token_cache, TokenCache
import pytest
import six
from test_shared_cache_credential import get_account_event


def test_callback():
    account = get_account_event("username", "uid", "utid")
    callback = Mock()
    cache = TokenCache(update_callback=callback)
    cache._cache.add(account)

    # the precise call count is an MSAL implementation detail
    assert callback.called


def test_serialization():
    account = get_account_event("username", "uid", "utid")

    def on_update(cache):
        data = serialize_token_cache(cache)
        assert isinstance(data, six.binary_type)

        deserialized_cache = deserialize_token_cache(data)
        round_trip_data = serialize_token_cache(deserialized_cache)
        assert isinstance(round_trip_data, six.binary_type)
        assert sorted(round_trip_data) == sorted(data)


    callback = Mock(wraps=on_update)
    cache = TokenCache(update_callback=callback)
    cache._cache.add(account)

    assert callback.called


@patch(PersistentTokenCache.__module__ + ".sys.platform", "linux2")
def test_allow_unencrypted_linux():
    """The cache should use an unencrypted cache only when the user opts in and encryption is unavailable.

    This test was written when Linux was the only platform on which encryption may not be available.
    """

    mock_get_location = Mock(return_value="...")
    mock_persistence = Mock(return_value=Mock(get_location=mock_get_location))
    mock_extensions = Mock(LibsecretPersistence=mock_persistence, FilePersistence=mock_persistence)

    with patch(PersistentTokenCache.__module__ + ".msal_extensions", mock_extensions):

        # the credential should prefer an encrypted cache even when the user allows an unencrypted one
        cache = PersistentTokenCache(allow_unencrypted_storage=True)
        assert mock_extensions.PersistedTokenCache.called_with(mock_extensions.LibsecretPersistence)

        mock_extensions.PersistedTokenCache.reset_mock()

        # (when LibsecretPersistence's dependencies aren't available, constructing it raises ImportError)
        mock_extensions.LibsecretPersistence = Mock(side_effect=ImportError, get_location=mock_get_location)

        # encryption unavailable, no opt in to unencrypted cache -> PersistentTokenCache should raise
        with pytest.raises(ValueError):
            PersistentTokenCache()

        PersistentTokenCache(allow_unencrypted_storage=True)
        assert mock_extensions.PersistedTokenCache.called_with(mock_extensions.FilePersistence)


def test_unsupported_platform():
    """Constructing PersistentTokenCache on an unsupported platform should raise an exception"""

    with patch(PersistentTokenCache.__module__ + ".sys.platform", "commodore64"):
        with pytest.raises(NotImplementedError):
            PersistentTokenCache()
        with pytest.raises(NotImplementedError):
            PersistentTokenCache(allow_unencrypted_storage=True)
