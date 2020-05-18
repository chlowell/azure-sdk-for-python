# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import abc
from typing import TYPE_CHECKING

try:
    ABC = abc.ABC
except AttributeError:  # Python 2.7
    ABC = abc.ABCMeta("ABC", (object,), {"__slots__": ()})  # type: ignore

if TYPE_CHECKING:
    # pylint:disable=unused-import,ungrouped-imports
    from typing import Any


class ClientSecretCredentialBase(ABC):
    def __init__(self, tenant_id, client_id, client_secret, **kwargs):
        # type: (str, str, str, **Any) -> None
        if not client_id:
            raise ValueError("client_id should be the id of an Azure Active Directory application")
        if not client_secret:
            raise ValueError("secret should be an Azure Active Directory application's client secret")
        if not tenant_id:
            raise ValueError(
                "tenant_id should be an Azure Active Directory tenant's id (also called its 'directory id')"
            )

        self._client = self._get_auth_client(tenant_id, client_id, **kwargs)
        self._secret = client_secret

    @abc.abstractmethod
    def _get_auth_client(self, tenant_id, client_id, **kwargs):
        pass
