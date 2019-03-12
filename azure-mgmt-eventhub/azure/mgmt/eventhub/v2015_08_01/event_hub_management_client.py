# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.service_client import SDKClient
from msrest import Serializer, Deserializer
from msrestazure import AzureConfiguration
from .version import VERSION
from .operations.operations import Operations
from .operations.namespaces_operations import NamespacesOperations
from .operations.event_hubs_operations import EventHubsOperations
from .operations.consumer_groups_operations import ConsumerGroupsOperations
from . import models


class EventHubManagementClientConfiguration(AzureConfiguration):
    """Configuration for EventHubManagementClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Subscription credentials that uniquely identify a
     Microsoft Azure subscription. The subscription ID forms part of the URI
     for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        if credentials is None:
            raise ValueError("Parameter 'credentials' must not be None.")
        if subscription_id is None:
            raise ValueError("Parameter 'subscription_id' must not be None.")
        if not base_url:
            base_url = 'https://management.azure.com'

        super(EventHubManagementClientConfiguration, self).__init__(base_url)

        self.add_user_agent('azure-mgmt-eventhub/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.subscription_id = subscription_id


class EventHubManagementClient(SDKClient):
    """Azure Event Hubs client

    :ivar config: Configuration for client.
    :vartype config: EventHubManagementClientConfiguration

    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.eventhub.v2015_08_01.operations.Operations
    :ivar namespaces: Namespaces operations
    :vartype namespaces: azure.mgmt.eventhub.v2015_08_01.operations.NamespacesOperations
    :ivar event_hubs: EventHubs operations
    :vartype event_hubs: azure.mgmt.eventhub.v2015_08_01.operations.EventHubsOperations
    :ivar consumer_groups: ConsumerGroups operations
    :vartype consumer_groups: azure.mgmt.eventhub.v2015_08_01.operations.ConsumerGroupsOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Subscription credentials that uniquely identify a
     Microsoft Azure subscription. The subscription ID forms part of the URI
     for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = EventHubManagementClientConfiguration(credentials, subscription_id, base_url)
        super(EventHubManagementClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2015-08-01'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.namespaces = NamespacesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.event_hubs = EventHubsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.consumer_groups = ConsumerGroupsOperations(
            self._client, self.config, self._serialize, self._deserialize)
