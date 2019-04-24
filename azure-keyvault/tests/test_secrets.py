# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

from devtools_testutils import ResourceGroupPreparer
from keyvault_preparer import KeyVaultPreparer
from keyvault_testcase import KeyvaultTestCase
from azure.core.exceptions import HttpRequestError

from dateutil import parser as date_parse
import time


class KeyVaultSecretTest(KeyvaultTestCase):

    def _assert_secret_attributes_equal(self, s1, s2):
        self.assertEqual(s1.id , s2.id)
        self.assertEqual(s1.content_type, s2.content_type)
        self.assertEqual(s1.enabled, s2.enabled)
        self.assertEqual(s1.not_before, s2.not_before)
        self.assertEqual(s1.expires, s2.expires)
        self.assertEqual(s1.created, s2.created)
        self.assertEqual(s1.updated, s2.updated)
        self.assertEqual(s1.recovery_level, s2.recovery_level)
        self.assertEqual(s1.key_id, s2.key_id)

    def _validate_secret_bundle(self, bundle, vault, secret_name, secret_value):
        prefix = "/".join(s.strip("/") for s in [vault, "secrets", secret_name])
        id = bundle.id
        self.assertTrue(id.index(prefix) == 0,
                        "String should start with '{}', but value is '{}'".format(prefix, id))
        self.assertEqual(bundle.value, secret_value,
                         "value should be '{}', but is '{}'".format(secret_value, bundle.value))
        self.assertTrue(bundle.created and bundle.updated,
                        'Missing required date attributes.')

    def _validate_secret_list(self, secrets, expected):
        for secret in secrets:
            # TODO: what if secrets contains unexpected entries?
            if secret.id in expected.keys():
                expected_secret = expected[secret.id]
                self._assert_secret_attributes_equal(expected_secret, secret)
                del expected[secret.id]

    @ResourceGroupPreparer()
    @KeyVaultPreparer()
    # @asyncify
    def test_secret_crud_operations(self, vault_client, **kwargs):
        self.assertIsNotNone(vault_client)
        client = vault_client.secrets
        secret_name = 'crud-secret'
        secret_value = self.get_resource_name('crud_secret_value')

        # create secret
        created = client.set_secret(secret_name, secret_value)
        self._validate_secret_bundle(created, vault_client.vault_url, secret_name, secret_value)

        # get secret without version
        self._assert_secret_attributes_equal(created, client.get_secret(created.name, ''))

        # get secret with version
        self._assert_secret_attributes_equal(created, client.get_secret(created.name, created.version))

        def _update_secret(secret):
            content_type = 'text/plain'
            expires = date_parse.parse('2050-02-02T08:00:00.000Z')
            tags = {'foo': 'updated tag'}
            secret_bundle = client.update_secret_attributes(
                secret.name, secret.version,
                content_type=content_type,
                expires=expires,
                tags=tags)
            self.assertEqual(tags, secret_bundle.tags)
            self.assertEqual(secret.id, secret_bundle.id)
            self.assertNotEqual(secret.updated, secret_bundle.updated)
            return secret_bundle

        # update secret with version
        if self.is_live:
            # wait a second to ensure the secret's update time won't equal its creation time
            time.sleep(1)
        updated = _update_secret(created)

        # delete secret
        client.delete_secret(updated.name)

        # TestCase.assertRaisesRegexp was deprecated in 3.2
        if hasattr(self, "assertRaisesRegex"):
            assertRaises = self.assertRaisesRegex
        else:
            assertRaises = self.assertRaisesRegexp

        # deleted secret isn't found
        # with assertRaises(HttpRequestError, r"(?i)not found"):
        #     client.get_secret(updated.name, '')

    @ResourceGroupPreparer()
    @KeyVaultPreparer()
    def test_secret_list(self, vault_client, **kwargs):
        self.assertIsNotNone(vault_client)
        client = vault_client.secrets

        max_secrets = self.list_test_size
        expected = {}

        # create many secrets
        for x in range(0, max_secrets):
            secret_name = 'sec{}'.format(x)
            secret_value = self.get_resource_name('secVal{}'.format(x))
            secret = None
            while not secret:
                secret = client.set_secret(secret_name, secret_value)
                expected[secret.id] = secret

        # list secrets
        result = list(client.list_secrets(max_secrets))
        self._validate_secret_list(result, expected)

    @ResourceGroupPreparer()
    @KeyVaultPreparer()
    def test_list_versions(self, vault_client, **kwargs):
        self.assertIsNotNone(vault_client)
        client = vault_client.secrets
        secret_name = self.get_resource_name('sec')
        secret_value = self.get_resource_name('secVal')

        max_secrets = self.list_test_size
        expected = {}

        # create many secret versions
        for _ in range(0, max_secrets):
            secret = None
            while not secret:
                secret = client.set_secret(secret_name, secret_value)
                expected[secret.id] = secret

        # list secret versions
        self._validate_secret_list(list(client.list_secret_versions(secret_name)), expected)

    @ResourceGroupPreparer()
    @KeyVaultPreparer()
    def test_backup_restore(self, vault_client, **kwargs):
        self.assertIsNotNone(vault_client)
        client = vault_client.secrets
        secret_name = self.get_resource_name('secbak')
        secret_value = self.get_resource_name('secVal')

        # create secret
        created_bundle = client.set_secret(secret_name, secret_value)

        # backup secret
        secret_backup = client.backup_secret(created_bundle.name)
        self.assertIsNotNone(secret_backup, 'secret_backup')

        # delete secret
        client.delete_secret(created_bundle.name)

        # restore secret
        restored = client.restore_secret(secret_backup)
        self._assert_secret_attributes_equal(created_bundle, restored)

    @ResourceGroupPreparer()
    @KeyVaultPreparer(enable_soft_delete=True)
    def test_recover_purge(self, vault_client, **kwargs):
        self.assertIsNotNone(vault_client)
        client = vault_client.secrets

        secrets = {}

        # create secrets to recover
        for i in range(0, self.list_test_size):
            secret_name = self.get_resource_name('secrec{}'.format(str(i)))
            secret_value = self.get_resource_name('secval{}'.format((str(i))))
            secrets[secret_name] = client.set_secret(secret_name, secret_value)

        # create secrets to purge
        for i in range(0, self.list_test_size):
            secret_name = self.get_resource_name('secprg{}'.format(str(i)))
            secret_value = self.get_resource_name('secval{}'.format((str(i))))
            secrets[secret_name] = client.set_secret(secret_name, secret_value)

        # delete all secrets
        for secret_name in secrets.keys():
            client.delete_secret(secret_name)

        if not self.is_playback():
            time.sleep(20)

        # validate all our deleted secrets are returned by list_deleted_secrets
        deleted = [s.name for s in client.list_deleted_secrets()]
        self.assertTrue(all(s in deleted for s in secrets.keys()))

        # recover select secrets
        for secret_name in [s for s in secrets.keys() if s.startswith('secrec')]:
            client.recover_deleted_secret(secret_name)

        # purge select secrets
        for secret_name in [s for s in secrets.keys() if s.startswith('secprg')]:
            client.purge_deleted_secret(secret_name)

        if not self.is_playback():
            time.sleep(20)

        # validate none of our purged secrets are returned by list_deleted_secrets
        deleted = [s.name for s in client.list_deleted_secrets()]
        self.assertTrue(not any(s in deleted for s in secrets.keys()))

        # validate the recovered secrets
        expected = {k: v for k, v in secrets.items() if k.startswith('secrec')}
        actual = {k: client.get_secret(k, "") for k in expected.keys()}
        self.assertEqual(len(set(expected.keys()) & set(actual.keys())), len(expected))



import functools
import ast
import inspect
import unittest


def asyncify(test_fn):
    """Synchronous wrapper for async test methods. Used to avoid making changes
       upstream to AbstractPreparer (which doesn't await the functions it wraps)
    """
    @functools.wraps(test_fn)
    def run(test_class_instance, *args, **kwargs):
        try:
            import asyncio
            from azure.keyvault.aio.vault_client import VaultClient
        except ImportError:
            return

        vault_client = kwargs.get("vault_client")
        # create an async client
        credentials = test_class_instance.settings.get_credentials(resource="https://vault.azure.net")
        aio_client = VaultClient(vault_client.vault_url, credentials)

        # execute the test asynchronously
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(test_fn(test_class_instance, vault_client=aio_client))

    return run


class AsyncTests(KeyVaultSecretTest, unittest.TestCase):
    def __init__(self, method_names, config_file=None,
                 recording_dir=None, recording_name=None,
                 recording_processors=None, replay_processors=None,
                 recording_patches=None, replay_patches=None):
        super(AsyncTests, self).__init__(method_names, config_file,
                                         recording_dir, recording_name,
                                         recording_processors, replay_processors,
                                         recording_patches, replay_patches)

        # idea: dynamically modify all the inherited test methods
        # need to await all coroutine expressions
        method_names = [name for (name, value) in inspect.getmembers(self) if inspect.ismethod(value)]
        for name in method_names:
            setattr(self, name, self.foo_test)

    def foo_test(self, **kwargs):
        print("called foo_test")

    def assertEqual(self, *args):
        # idea: defer asserts until after coroutines complete
        # print("called assertEqual with {}".format(list(args)))
        super(KeyVaultSecretTest, self).assertEqual(*args)


# causes pytest to collect (and execute) a second definition of all the above tests
KeyvaultTestCase = AsyncTests


class Awaitify(ast.NodeTransformer):

    def visit_Call(self, node: ast.Call):
        self.generic_visit(node)

        return node

