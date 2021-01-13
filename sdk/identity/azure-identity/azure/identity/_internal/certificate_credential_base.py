# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import abc

import six

from . import AadClientCertificate
from .._internal import validate_tenant_id
from .._token_cache import TokenCache

try:
    ABC = abc.ABC
except AttributeError:  # Python 2.7, abc exists, but not ABC
    ABC = abc.ABCMeta("ABC", (object,), {"__slots__": ()})  # type: ignore

try:
    from typing import TYPE_CHECKING
except ImportError:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    # pylint:disable=unused-import
    from typing import Any


class CertificateCredentialBase(ABC):
    def __init__(self, tenant_id, client_id, certificate_path, **kwargs):
        # type: (str, str, str, **Any) -> None
        validate_tenant_id(tenant_id)
        if not certificate_path:
            raise ValueError(
                "'certificate_path' must be the path to a PEM file containing an x509 certificate and its private key"
            )

        super(CertificateCredentialBase, self).__init__()

        password = kwargs.pop("password", None)
        if isinstance(password, six.text_type):
            password = password.encode(encoding="utf-8")

        with open(certificate_path, "rb") as f:
            pem_bytes = f.read()

        self._certificate = AadClientCertificate(pem_bytes, password=password)

        cache = kwargs.pop("token_cache", None) or TokenCache()  # type: TokenCache
        self._client = self._get_auth_client(tenant_id, client_id, cache=cache._cache, **kwargs)
        self._client_id = client_id

    @abc.abstractmethod
    def _get_auth_client(self, tenant_id, client_id, **kwargs):
        pass
