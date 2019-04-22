# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
from typing import Any, Mapping, Optional, AsyncGenerator

from azure.core.configuration import Configuration
from azure.core.pipeline.policies import UserAgentPolicy, AsyncRetryPolicy, AsyncRedirectPolicy
from azure.core.pipeline.transport import AsyncioRequestsTransport
from azure.core.pipeline import AsyncPipeline
from azure.keyvault._generated.v7_0.aio import KeyVaultClient
from azure.keyvault._internal import _BearerTokenCredentialPolicy

from ..._generated.v7_0.models import SecretAttributes as _SecretAttributes, KeyVaultErrorException

from ...secrets._models import Secret, DeletedSecret, SecretAttributes


class SecretClient:
    @staticmethod
    def create_config(**kwargs):
        config = Configuration(**kwargs)
        config.user_agent = UserAgentPolicy("SecretClient", **kwargs)
        config.headers = None
        config.retry = AsyncRetryPolicy(**kwargs)
        config.redirect = AsyncRedirectPolicy(**kwargs)
        return config

    def __init__(self, vault_url, credentials, config=None, **kwargs):
        """Creates a SecretClient with the for managing secrets in the specified vault.

        :param credentials:  A credential or credential provider which can be used to authenticate to the vault
        :type credentials: azure.authenctication.Credential or azure.authenctication.CredentialProvider
        :param str vault_url: The url of the vault
        :param azure.core.configuration.Configuration config:  The configuration for the SecretClient
        """
        if not credentials:
            raise ValueError("credentials")

        if not vault_url:
            raise ValueError("vault_url")

        self._vault_url = vault_url

        config = config or SecretClient.create_config(**kwargs)
        transport = AsyncioRequestsTransport(config)
        policies = [
            config.user_agent_policy,
            config.headers_policy,
            _BearerTokenCredentialPolicy(credentials),
            config.redirect_policy,
            config.retry_policy,
            # config.logging,
        ]
        self._pipeline = AsyncPipeline(transport, policies=policies)
        self._client = KeyVaultClient(credentials, pipeline=self._pipeline)

    @property
    def vault_url(self):
        return self._vault_url

    async def get_secret(self, name, version, **kwargs):
        """Get a specified from the vault.

        The GET operation is applicable to any secret stored in Azure Key
        Vault. This operation requires the secrets/get permission.

        :param str name: The name of the secret.
        :param str version: The version of the secret.  If not specified the latest version of
            the secret is returned
        :return: Secret
        :rtype: ~azure.keyvault.secrets.Secret
        :raises:
         :class:`KeyVaultErrorException<azure.keyvault.KeyVaultErrorException>`
        """
        try:
            bundle = await self._client.get_secret(self.vault_url, name, version, kwargs)
            return Secret.from_secret_bundle(bundle)
        except KeyVaultErrorException as ex:
            raise  # TODO

    async def set_secret(
        self, name, value, content_type=None, enabled=None, not_before=None, expires=None, tags=None, **kwargs
    ):
        """Sets a secret in the vault.

        The SET operation adds a secret to the Azure Key Vault. If the named
        secret already exists, Azure Key Vault creates a new version of that
        secret. This operation requires the secrets/set permission.

        :param str name: The name of the secret
        :param str value: The value of the secret
        :param str content_type: Type of the secret value such as a password
        :param attributes: The secret management attributes
        :type attributes: ~azure.keyvault.secrets.SecretAttributes
        :param dict[str, str] tags: Application specific metadata in the form of key-value
            deserialized response
        :param operation_config: :ref:`Operation configuration
            overrides<msrest:optionsforoperations>`.
        :return: The created secret
        :rtype: ~azure.keyvault.secret.Secret
        :raises:{
        :class:`azure.core.HttpRequestError`
        """
        try:
            if enabled is not None or not_before is not None or expires is not None:
                attributes = _SecretAttributes(enabled=enabled, not_before=not_before, expires=expires)
            else:
                attributes = None
            bundle = await self._client.set_secret(
                self.vault_url, name, value, secret_attributes=attributes, content_type=content_type, tags=tags
            )
            return Secret.from_secret_bundle(bundle)
        except KeyVaultErrorException as ex:
            raise

    async def update_secret_attributes(
        self, name, version, content_type=None, enabled=None, not_before=None, expires=None, tags=None, **kwargs
    ):
        try:
            if enabled is not None or not_before is not None or expires is not None:
                attributes = _SecretAttributes(enabled=enabled, not_before=not_before, expires=expires)
            else:
                attributes = None
            bundle = await self._client.update_secret(
                self.vault_url,
                name,
                secret_version=version,
                content_type=content_type,
                tags=tags,
                secret_attributes=attributes,
            )
            return SecretAttributes.from_secret_bundle(bundle)
        except KeyVaultErrorException as ex:
            raise

    def list_secrets(self, **kwargs: Mapping[str, Any]) -> AsyncGenerator[SecretAttributes, None]:
        """List secrets in the vault.

        The Get Secrets operation is applicable to the entire vault. However,
        only the latest secret identifier and its attributes are provided in the
        response. No secret values are returned and individual secret versions are
        not listed in the response.  This operation requires the secrets/list permission.

        :param max_page_size: Maximum number of results to return in a page. If
         not max_page_size, the service will return up to 25 results.
        :type maxresults: int
        :return: An iterator like instance of Secrets
        :rtype:
         ~azure.keyvault.secrets.SecretAttributesPaged[~azure.keyvault.secret.Secret]
        :raises:
         :class:`HttpRequestError<azure.core.HttpRequestError>`
        """
        try:
            max_results = kwargs.get("max_page_size")
            pages = self._client.get_secrets(self.vault_url, maxresults=max_results)
            return (SecretAttributes.from_secret_item(item) async for item in pages)
        except KeyVaultErrorException as ex:
            raise

    def list_secret_versions(self, name: str, **kwargs: Mapping[str, Any]) -> AsyncGenerator[SecretAttributes, None]:
        """List all versions of the specified secret.

        The full secret identifier and attributes are provided in the response.
        No values are returned for the secrets. This operations requires the
        secrets/list permission.

        :param name: The name of the secret.
        :type name: str
        :param max_page_size: Maximum number of results to return in a page. If
         not max_page_size, the service will return up to 25 results.
        :type maxresults: int
        :return: An iterator like instance of Secret
        :rtype:
         ~azure.keyvault.secrets.SecretAttributesPaged[~azure.keyvault.secret.Secret]
        :raises:
         :class:`HttpRequestError<azure.core.HttpRequestError>`
        """
        try:
            max_results = kwargs.get("max_page_size")
            pages = self._client.get_secret_versions(self.vault_url, name, maxresults=max_results)
            return (SecretAttributes.from_secret_item(item) async for item in pages)
        except KeyVaultErrorException as ex:
            raise

    async def backup_secret(self, name, **kwargs):
        """Backs up the specified secret.

        Requests that a backup of the specified secret be downloaded to the
        client. All versions of the secret will be downloaded. This operation
        requires the secrets/backup permission.

        :param str name: The name of the secret.
        :return: The raw bytes of the secret backup.
        :rtype: bytes
        :raises:
         :class:azure.core.HttpRequestError
        """
        try:
            backup_result = await self._client.backup_secret(self.vault_url, name)
            return backup_result.value
        except KeyVaultErrorException as ex:
            raise

    async def restore_secret(self, backup, **kwargs):
        """Restores a backed up secret to a vault.

        Restores a backed up secret, and all its versions, to a vault. This
        operation requires the secrets/restore permission.

        :param bytes backup: The raw bytes of the secret backup
        :return: The restored secret
        :rtype: ~azure.keyvault.secrets.Secret
        :raises:
         :class:azure.core.HttpRequestError
        """
        try:
            bundle = await self._client.restore_secret(self.vault_url, backup)
            return SecretAttributes.from_secret_bundle(bundle)
        except KeyVaultErrorException as ex:
            raise

    async def delete_secret(self, name, **kwargs):
        # type: (str, Mapping[str, Any]) -> DeletedSecret
        try:
            bundle = await self._client.delete_secret(self.vault_url, name)
            return DeletedSecret.from_deleted_secret_bundle(bundle)
        except KeyVaultErrorException as ex:
            raise

    async def get_deleted_secret(self, name, **kwargs):
        # type: (str, Mapping[str, Any]) -> DeletedSecret
        try:
            bundle = await self._client.get_deleted_secret(self.vault_url, name)
            return DeletedSecret.from_deleted_secret_bundle(bundle)
        except KeyVaultErrorException as ex:
            raise

    def list_deleted_secrets(self, **kwargs: Mapping[str, Any]) -> AsyncGenerator[DeletedSecret, None]:
        try:
            max_results = kwargs.get("max_page_size")
            pages = self._client.get_deleted_secrets(self.vault_url, maxresults=max_results)
            return (DeletedSecret.from_deleted_secret_item(item) async for item in pages)
        except KeyVaultErrorException as ex:
            raise

    async def purge_deleted_secret(self, name, **kwargs):
        # type: (str, Mapping[str, Any]) -> None
        try:
            await self._client.purge_deleted_secret(self.vault_url, name)
        except KeyVaultErrorException as ex:
            raise

    async def recover_deleted_secret(self, name, **kwargs):
        # type: (str, Mapping[str, Any]) -> SecretAttributes
        try:
            bundle = await self._client.recover_deleted_secret(self.vault_url, name)
            return SecretAttributes.from_secret_bundle(bundle)
        except KeyVaultErrorException as ex:
            raise
