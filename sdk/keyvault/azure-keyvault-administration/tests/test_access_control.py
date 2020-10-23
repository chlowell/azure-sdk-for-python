# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
from __future__ import print_function
import functools
import os
import uuid

try:
    from unittest import mock
except ImportError:  # python < 3.3
    import mock  # type: ignore

from azure.keyvault.administration import KeyVaultAccessControlClient, KeyVaultRoleScope
from devtools_testutils import KeyVaultPreparer, ResourceGroupPreparer
import pytest

from _shared.test_case import KeyVaultTestCase
from _shared.preparer import KeyVaultClientPreparer as _KeyVaultClientPreparer

AccessControlClientPreparer = functools.partial(_KeyVaultClientPreparer, KeyVaultAccessControlClient)


class AccessControlTests(KeyVaultTestCase):
    def __init__(self, *args, **kwargs):
        super(AccessControlTests, self).__init__(*args, **kwargs)
        if self.is_live:
            pytest.skip("test infrastructure can't yet create a Key Vault supporting the RBAC API")

    def get_replayable_uuid(self, replay_value):
        if self.is_live:
            value = str(uuid.uuid4())
            self.scrubber.register_name_pair(value, replay_value)
            return value
        return replay_value

    def get_service_principal_id(self):
        replay_value = "service-principal-id"
        if self.is_live:
            value = os.environ["AZURE_CLIENT_ID"]
            self.scrubber.register_name_pair(value, replay_value)
            return value
        return replay_value

    @ResourceGroupPreparer(random_name_enabled=True)
    @KeyVaultPreparer()
    @AccessControlClientPreparer()
    def test_list_role_definitions(self, client):
        definitions = [d for d in client.list_role_definitions(KeyVaultRoleScope.global_value)]
        assert len(definitions)

        for definition in definitions:
            assert "/" in definition.assignable_scopes
            assert definition.description is not None
            assert definition.id is not None
            assert definition.name is not None
            assert len(definition.permissions)
            assert definition.role_name is not None
            assert definition.role_type is not None
            assert definition.type is not None

    @ResourceGroupPreparer(random_name_enabled=True)
    @KeyVaultPreparer()
    @AccessControlClientPreparer()
    def test_role_assignment(self, client):
        scope = KeyVaultRoleScope.global_value
        definitions = [d for d in client.list_role_definitions(scope)]

        # assign an arbitrary role to the service principal authenticating these requests
        definition = definitions[0]
        principal_id = self.get_service_principal_id()
        name = self.get_replayable_uuid("some-uuid")

        created = client.create_role_assignment(scope, definition.id, principal_id, role_assignment_name=name)
        assert created.name == name
        assert created.principal_id == principal_id
        assert created.role_definition_id == definition.id
        assert created.scope == scope

        # should be able to get the new assignment
        got = client.get_role_assignment(scope, name)
        assert got.name == name
        assert got.principal_id == principal_id
        assert got.role_definition_id == definition.id
        assert got.scope == scope

        # new assignment should be in the list of all assignments
        matching_assignments = [
            a for a in client.list_role_assignments(scope) if a.assignment_id == created.assignment_id
        ]
        assert len(matching_assignments) == 1

        # delete the assignment
        deleted = client.delete_role_assignment(scope, created.name)
        assert deleted.name == created.name
        assert deleted.assignment_id == created.assignment_id
        assert deleted.scope == scope
        assert deleted.role_definition_id == created.role_definition_id

        assert not any(a for a in client.list_role_assignments(scope) if a.assignment_id == created.assignment_id)

    @ResourceGroupPreparer(random_name_enabled=True)
    @KeyVaultPreparer()
    @AccessControlClientPreparer()
    def test_samples(self, client):
        def print(*args):
            assert all(arg is not None for arg in args)

        # [START list_role_definitions]
        for role_definition in client.list_role_definitions():
            print(role_definition.role_name)
            print(role_definition.id)
        # [END list_role_definitions]

        assert role_definition  # should always be at least one definition

        principal_id = self.get_service_principal_id()
        with mock.patch(KeyVaultAccessControlClient.__module__ + ".uuid4", lambda: self.get_replayable_uuid("uuid")):
            # [START create_role_assignment]
            # this assignment will apply to all the Vault's keys
            scope = KeyVaultRoleScope.keys_value
            assignment = client.create_role_assignment(scope, role_definition.id, principal_id)
            # [END create_role_assignment]

        created_assignment = assignment
        name = assignment.name

        # [START get_role_assignment]
        assignment = client.get_role_assignment(scope, name)
        # [END get_role_assignment]

        assert assignment.name == created_assignment.assignment.name
        assert assignment.principal_id == created_assignment.assignment.principal_id
        assert assignment.scope == created_assignment.assignment.scope
        assert assignment.role_definition_id == role_definition.id

        # [START list_role_assignments]
        for assignment in client.list_role_assignments:
            print(assignment.name)
        # [END list_role_assignments]

        # [START delete_role_assignment]
        deleted_assignment = client.delete_role_assignment(assignment.scope, assignment.name)
        # [END delete_role_assignment]

        assert deleted_assignment.name == created_assignment.name
        assert deleted_assignment.assignment_id == created_assignment.assignment_id
        assert deleted_assignment.role_definition_id == created_assignment.role_definition_id
        assert deleted_assignment.scope == scope


def test_create_access_control_client():
    vault_url = "..."

    # [START create_access_control_client]
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.administration import KeyVaultAccessControlClient

    # This could be any credential from azure.identity
    credential = DefaultAzureCredential()
    client = KeyVaultAccessControlClient(vault_url, credential)
    # [END create_access_control_client]
