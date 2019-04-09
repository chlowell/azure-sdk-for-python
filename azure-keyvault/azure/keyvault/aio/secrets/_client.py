# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
import functools
import uuid

from azure.core.configuration import Configuration
from azure.core.pipeline.policies import (
    UserAgentPolicy,
    HeadersPolicy,
    AsyncRetryPolicy,
    AsyncRedirectPolicy,
    CredentialsPolicy,
    AsyncHTTPPolicy,
)
from azure.core.pipeline.transport import AioHttpTransport, HttpRequest
from azure.core.pipeline import AsyncPipeline
from azure.core.exceptions import ClientRequestError

from msrest import Serializer, Deserializer

from ...secrets._models import DeletedSecret, DeletedSecretPaged, Secret, SecretAttributesPaged, SecretAttributes

from ..._internal import _BackupResult, _SecretManagementAttributes, _USER_AGENT_STRING


class BearerTokenCredentialPolicy(AsyncHTTPPolicy):
    def __init__(self, credentials):
        self._credentials = credentials

    async def send(self, request, **kwargs):
        auth_header = "Bearer " + self._credentials.token["access_token"]
        request.http_request.headers["Authorization"] = auth_header

        return await self.next.send(request, **kwargs)


class SecretClient:

    _api_version = "7.0"

    @staticmethod
    def create_config(**kwargs):
        config = Configuration(**kwargs)
        config.user_agent = UserAgentPolicy(_USER_AGENT_STRING, **kwargs)
        config.retry = AsyncRetryPolicy(**kwargs)
        config.redirect = AsyncRedirectPolicy(**kwargs)
        return config

    def __init__(self, vault_url, credentials, config=None, **kwargs):
        if not credentials:
            raise ValueError("credentials")

        if not vault_url:
            raise ValueError("vault_url")

        self.vault_url = vault_url
        config = config or SecretClient.create_config(**kwargs)
        transport = AioHttpTransport(config.connection)
        policies = [config.user_agent, BearerTokenCredentialPolicy(credentials), config.redirect, config.retry]
        client_models = {
            "DeletedSecret": DeletedSecret,
            "DeletedSecretPaged": DeletedSecretPaged,
            "Secret": Secret,
            "SecretAttributes": SecretAttributes,
            "_SecretManagementAttributes": _SecretManagementAttributes,
            "_BackupResult": _BackupResult,
        }
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)
        self._pipeline = AsyncPipeline(transport, policies=policies)

    async def get_secret(self, name, version=None, **kwargs):
        url = "/".join([s.strip("/") for s in (self.vault_url, "secrets", name, version or "")])

        query_parameters = {"api-version": self._api_version}

        headers = {"Content-Type": "application/json; charset=utf-8", "x-ms-client-request-id": str(uuid.uuid1())}

        request = HttpRequest("GET", url, headers)

        request.format_parameters(query_parameters)

        response = (await self._pipeline.run(request, **kwargs)).http_response

        if response.status_code != 200:
            await response.load_body()
            raise ClientRequestError("Request failed status code {}.  {}".format(response.status_code, response.text()))

        return self._deserialize("Secret", response)

    async def set_secret(
        self, name, value, content_type=None, enabled=None, not_before=None, expires=None, tags=None, **kwargs
    ):
        management_attributes = _SecretManagementAttributes(enabled=enabled, not_before=not_before, expires=expires)
        secret = Secret(value=value, content_type=content_type, _management_attributes=management_attributes, tags=tags)

        url = "/".join([s.strip("/") for s in (self.vault_url, "secrets", name)])

        query_parameters = {"api-version": self._api_version}

        headers = {"Content-Type": "application/json; charset=utf-8", "x-ms-client-request-id": str(uuid.uuid1())}

        request_body = self._serialize.body(secret, "Secret")

        request = HttpRequest("PUT", url, headers, data=request_body)

        request.format_parameters(query_parameters)

        response = (await self._pipeline.run(request, **kwargs)).http_response

        if response.status_code != 200:
            await response.load_body()
            raise ClientRequestError("Request failed status code {}.  {}".format(response.status_code, response.body()))

        return self._deserialize("Secret", response)

    async def update_secret_attributes(
        self, name, version, content_type=None, enabled=None, not_before=None, expires=None, tags=None, **kwargs
    ):
        # type: () -> SecretAttributes
        url = "/".join([s.strip("/") for s in (self.vault_url, "secrets", name, version)])

        management_attributes = _SecretManagementAttributes(enabled=enabled, not_before=not_before, expires=expires)
        secret = Secret(content_type=content_type, _management_attributes=management_attributes, tags=tags)

        query_parameters = {"api-version": self._api_version}

        headers = {"Content-Type": "application/json; charset=utf-8", "x-ms-client-request-id": str(uuid.uuid1())}

        request_body = self._serialize.body(secret, "Secret")

        request = HttpRequest("PATCH", url, headers, data=request_body)

        request.format_parameters(query_parameters)

        response = (await self._pipeline.run(request, **kwargs)).http_response

        if response.status_code != 200:
            await response.load_body()
            raise ClientRequestError("Request failed status code {}.  {}".format(response.status_code, response.text()))

        return self._deserialize("SecretAttributes", response)

    async def list_secrets(self, max_page_size=None, **kwargs):
        url = "{}/secrets".format(self.vault_url)
        paging = functools.partial(self._internal_paging, url, max_page_size)
        return SecretAttributesPaged(paging, self._deserialize.dependencies)

    async def list_secret_versions(self, name, max_page_size=None, **kwargs):
        url = "{}/secrets/{}/versions".format(self.vault_url, name)
        paging = functools.partial(self._internal_paging, url, max_page_size)
        return SecretAttributesPaged(paging, self._deserialize.dependencies)

    async def backup_secret(self, name, **kwargs):
        url = "/".join([s.strip("/") for s in (self.vault_url, "secrets", name, "backup")])

        query_parameters = {"api-version": self._api_version}

        headers = {"Content-Type": "application/json; charset=utf-8", "x-ms-client-request-id": str(uuid.uuid1())}

        request = HttpRequest("POST", url, headers)

        request.format_parameters(query_parameters)

        response = (await self._pipeline.run(request, **kwargs)).http_response

        if response.status_code != 200:
            await response.load_body()
            raise ClientRequestError("Request failed status code {}.  {}".format(response.status_code, response.text()))

        return self._deserialize("_BackupResult", response).value

    async def restore_secret(self, backup, **kwargs):
        backup = _BackupResult(value=backup)

        url = "/".join([s.strip("/") for s in (self.vault_url, "secrets", "restore")])

        query_parameters = {"api-version": self._api_version}

        headers = {"Content-Type": "application/json; charset=utf-8", "x-ms-client-request-id": str(uuid.uuid1())}

        request_body = self._serialize.body(backup, "_BackupResult")

        request = HttpRequest("POST", url, headers, data=request_body)

        request.format_parameters(query_parameters)

        response = (await self._pipeline.run(request, **kwargs)).http_response

        if response.status_code != 200:
            await response.load_body()
            raise ClientRequestError("Request failed status code {}.  {}".format(response.status_code, response.text()))

        return self._deserialize("SecretAttributes", response)

    async def delete_secret(self, name, **kwargs):
        # type: (str, Mapping[str, Any]) -> DeletedSecret
        url = "/".join([self.vault_url, "secrets", name])

        request = HttpRequest("DELETE", url)
        request.format_parameters({"api-version": self._api_version})
        response = (await self._pipeline.run(request, **kwargs)).http_response
        if response.status_code != 200:
            await response.load_body()
            raise ClientRequestError("Request failed with code {}: '{}'".format(response.status_code, response.text()))
        deleted_secret = self._deserialize("DeletedSecret", response)

        return deleted_secret

    async def get_deleted_secret(self, name, **kwargs):
        # type: (str, Mapping[str, Any]) -> DeletedSecret
        url = "/".join([self.vault_url, "deletedsecrets", name])

        request = HttpRequest("GET", url)
        request.format_parameters({"api-version": self._api_version})
        response = (await self._pipeline.run(request, **kwargs)).http_response
        if response.status_code != 200:
            await response.load_body()
            raise ClientRequestError("Request failed with code {}: '{}'".format(response.status_code, response.text()))
        deleted_secret = self._deserialize("DeletedSecret", response)

        return deleted_secret

    async def list_deleted_secrets(self, max_page_size=None, **kwargs):
        # type: (Optional[int], Mapping[str, Any]) -> DeletedSecretPaged
        url = "{}/deletedsecrets".format(self.vault_url)
        paging = functools.partial(self._internal_paging, url, max_page_size)
        return DeletedSecretPaged(paging, self._deserialize.dependencies)

    async def purge_deleted_secret(self, name, **kwargs):
        # type: (str, Mapping[str, Any]) -> None
        url = "/".join([self.vault_url, "deletedsecrets", name])

        request = HttpRequest("DELETE", url)
        request.format_parameters({"api-version": self._api_version})

        response = (await self._pipeline.run(request, **kwargs)).http_response
        if response.status_code != 204:
            raise ClientRequestError("Request failed with code {}: '{}'".format(response.status_code, response.text()))

        return

    async def recover_deleted_secret(self, name, **kwargs):
        # type: (str, Mapping[str, Any]) -> SecretAttributes
        url = "/".join([self.vault_url, "deletedsecrets", name, "recover"])

        request = HttpRequest("POST", url)
        request.format_parameters({"api-version": self._api_version})

        response = (await self._pipeline.run(request, **kwargs)).http_response
        if response.status_code != 200:
            await response.load_body()
            raise ClientRequestError("Request failed with code {}: '{}'".format(response.status_code, response.text()))

        secret_attributes = self._deserialize("SecretAttributes", response)

        return secret_attributes

    async def _internal_paging(self, url, max_page_size, next_link=None, raw=False, **kwargs):
        # type: (str, int, Optional[str], Optional[bool], Mapping[str, Any]) -> HttpResponse
        if next_link:
            url = next_link
            query_parameters = {}
        else:
            query_parameters = {"api-version": self._api_version}
            if max_page_size is not None:
                query_parameters["maxresults"] = str(max_page_size)

        headers = {"x-ms-client-request-id": str(uuid.uuid1())}

        request = HttpRequest("GET", url, headers)
        request.format_parameters(query_parameters)

        response = (await self._pipeline.run(request, **kwargs)).http_response

        if response.status_code != 200:
            await response.load_body()
            raise ClientRequestError("Request failed with code {}: '{}'".format(response.status_code, response.text()))

        return response
