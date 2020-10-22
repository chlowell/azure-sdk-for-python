# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# -------------------------------------
import functools

from azure.keyvault.secrets.aio import SecretClient

from _shared.preparer import CachedKeyVaultPreparer
from _shared.preparer_async import KeyVaultClientPreparer as _KeyVaultClientPreparer
from _shared.test_case_async import KeyVaultTestCase


# pre-apply the client_cls positional argument so it needn't be explicitly passed below
KeyVaultClientPreparer = functools.partial(_KeyVaultClientPreparer, SecretClient)


def print(*args):
    assert all(arg is not None for arg in args)


def test_create_secret_client():
    vault_url = "vault_url"
    # pylint:disable=unused-variable

    # [START create_secret_client]
    from azure.identity.aio import DefaultAzureCredential
    from azure.keyvault.secrets.aio import SecretClient

    # Create a SecretClient using default Azure credentials
    credential = DefaultAzureCredential()
    secret_client = SecretClient(vault_url, credential)
    # [END create_secret_client]


class TestExamplesKeyVault(KeyVaultTestCase):
    @CachedKeyVaultPreparer()
    @KeyVaultClientPreparer()
    async def test_example_secret_crud_operations(self, client, **kwargs):
        secret_client = client
        secret_name = self.get_resource_name("secret")

        # [START set_secret]
        from dateutil import parser as date_parse

        expires_on = date_parse.parse("2050-02-02T08:00:00.000Z")

        # create a secret, setting optional arguments
        secret = await secret_client.set_secret(secret_name, "secret-value", expires_on=expires_on)

        print(secret.name)
        print(secret.properties.version)
        print(secret.properties.expires_on)
        # [END set_secret]

        # [START get_secret]
        # get the latest version of a secret
        secret = await secret_client.get_secret(secret_name)

        # alternatively, specify a version
        secret = await secret_client.get_secret(secret_name, secret.properties.version)

        print(secret.id)
        print(secret.name)
        print(secret.properties.version)
        print(secret.properties.vault_url)
        # [END get_secret]

        # [START update_secret]
        # update attributes of an existing secret
        content_type = "text/plain"
        tags = {"foo": "updated tag"}
        updated_secret_properties = await secret_client.update_secret_properties(
            secret_name, content_type=content_type, tags=tags
        )

        print(updated_secret_properties.version)
        print(updated_secret_properties.updated_on)
        print(updated_secret_properties.content_type)
        print(updated_secret_properties.tags)
        # [END update_secret]

        # [START delete_secret]
        deleted_secret = await secret_client.delete_secret(secret_name)

        print(deleted_secret.name)
        print(deleted_secret.deleted_date)
        print(deleted_secret.scheduled_purge_date)
        print(deleted_secret.recovery_id)
        # [END delete_secret]

    @CachedKeyVaultPreparer()
    @KeyVaultClientPreparer()
    async def test_example_secret_list_operations(self, client, **kwargs):
        secret_client = client

        for i in range(7):
            await secret_client.set_secret(self.get_resource_name("secret{}".format(i)), "value{}".format(i))

        # [START list_secrets]
        secrets = secret_client.list_properties_of_secrets()
        async for secret in secrets:
            # the list doesn't include values or versions of the secrets
            print(secret.id)
            print(secret.name)
            print(secret.enabled)
        # [END list_secrets]

        secret_name = secret.name
        # pylint: disable=unused-variable

        # [START list_properties_of_secret_versions]
        secret_versions = secret_client.list_properties_of_secret_versions(secret_name)
        async for secret in secret_versions:
            # the list doesn't include the values at each version
            print(secret.id)
            print(secret.enabled)
            print(secret.updated_on)
        # [END list_properties_of_secret_versions]

        # [START list_deleted_secrets]
        deleted_secrets = secret_client.list_deleted_secrets()
        async for secret in deleted_secrets:
            # the list doesn't include values or versions of the deleted secrets
            print(secret.id)
            print(secret.name)
            print(secret.scheduled_purge_date)
            print(secret.recovery_id)
            print(secret.deleted_date)
        # [END list_deleted_secrets]

    @CachedKeyVaultPreparer()
    @KeyVaultClientPreparer()
    async def test_example_secrets_backup_restore(self, client, **kwargs):
        secret_client = client
        created_secret = await secret_client.set_secret(self.get_resource_name("secret"), "secret-value")
        secret_name = created_secret.name

        # [START backup_secret]
        # backup_secret returns the raw bytes of the backed up secret
        secret_backup = await secret_client.backup_secret(secret_name)
        print(secret_backup)
        # [END backup_secret]

        await secret_client.delete_secret(secret_name)
        await secret_client.purge_deleted_secret(secret_name)

        import asyncio
        await asyncio.sleep(10)

        # [START restore_secret_backup]
        restored_secret = await secret_client.restore_secret_backup(secret_backup)
        print(restored_secret.id)
        print(restored_secret.version)
        # [END restore_secret_backup]

    @CachedKeyVaultPreparer()
    @KeyVaultClientPreparer()
    async def test_example_secrets_recover(self, client, **kwargs):
        secret_client = client
        created_secret = await secret_client.set_secret(self.get_resource_name("secret"), "secret-value")
        secret_name = created_secret.name
        await secret_client.delete_secret(secret_name)

        # [START get_deleted_secret]
        deleted_secret = await secret_client.get_deleted_secret(secret_name)
        print(deleted_secret.name)
        # [END get_deleted_secret]

        # [START recover_deleted_secret]
        recovered_secret = await secret_client.recover_deleted_secret(secret_name)
        print(recovered_secret.id)
        print(recovered_secret.name)
        # [END recover_deleted_secret]
