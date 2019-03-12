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

from msrest.serialization import Model


class EventData(Model):
    """The Azure event log entries are of type EventData.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar authorization: The sender authorization information.
    :vartype authorization: ~azure.mgmt.monitor.models.SenderAuthorization
    :ivar claims: key value pairs to identify ARM permissions.
    :vartype claims: dict[str, str]
    :ivar caller: the email address of the user who has performed the
     operation, the UPN claim or SPN claim based on availability.
    :vartype caller: str
    :ivar description: the description of the event.
    :vartype description: str
    :ivar id: the Id of this event as required by ARM for RBAC. It contains
     the EventDataID and a timestamp information.
    :vartype id: str
    :ivar event_data_id: the event data Id. This is a unique identifier for an
     event.
    :vartype event_data_id: str
    :ivar correlation_id: the correlation Id, usually a GUID in the string
     format. The correlation Id is shared among the events that belong to the
     same uber operation.
    :vartype correlation_id: str
    :ivar event_name: the event name. This value should not be confused with
     OperationName. For practical purposes, OperationName might be more
     appealing to end users.
    :vartype event_name: ~azure.mgmt.monitor.models.LocalizableString
    :ivar category: the event category.
    :vartype category: ~azure.mgmt.monitor.models.LocalizableString
    :ivar http_request: the HTTP request info. Usually includes the
     'clientRequestId', 'clientIpAddress' (IP address of the user who initiated
     the event) and 'method' (HTTP method e.g. PUT).
    :vartype http_request: ~azure.mgmt.monitor.models.HttpRequestInfo
    :ivar level: the event level. Possible values include: 'Critical',
     'Error', 'Warning', 'Informational', 'Verbose'
    :vartype level: str or ~azure.mgmt.monitor.models.EventLevel
    :ivar resource_group_name: the resource group name of the impacted
     resource.
    :vartype resource_group_name: str
    :ivar resource_provider_name: the resource provider name of the impacted
     resource.
    :vartype resource_provider_name:
     ~azure.mgmt.monitor.models.LocalizableString
    :ivar resource_id: the resource uri that uniquely identifies the resource
     that caused this event.
    :vartype resource_id: str
    :ivar resource_type: the resource type
    :vartype resource_type: ~azure.mgmt.monitor.models.LocalizableString
    :ivar operation_id: It is usually a GUID shared among the events
     corresponding to single operation. This value should not be confused with
     EventName.
    :vartype operation_id: str
    :ivar operation_name: the operation name.
    :vartype operation_name: ~azure.mgmt.monitor.models.LocalizableString
    :ivar properties: the set of <Key, Value> pairs (usually a
     Dictionary<String, String>) that includes details about the event.
    :vartype properties: dict[str, str]
    :ivar status: a string describing the status of the operation. Some
     typical values are: Started, In progress, Succeeded, Failed, Resolved.
    :vartype status: ~azure.mgmt.monitor.models.LocalizableString
    :ivar sub_status: the event sub status. Most of the time, when included,
     this captures the HTTP status code of the REST call. Common values are: OK
     (HTTP Status Code: 200), Created (HTTP Status Code: 201), Accepted (HTTP
     Status Code: 202), No Content (HTTP Status Code: 204), Bad Request(HTTP
     Status Code: 400), Not Found (HTTP Status Code: 404), Conflict (HTTP
     Status Code: 409), Internal Server Error (HTTP Status Code: 500), Service
     Unavailable (HTTP Status Code:503), Gateway Timeout (HTTP Status Code:
     504)
    :vartype sub_status: ~azure.mgmt.monitor.models.LocalizableString
    :ivar event_timestamp: the timestamp of when the event was generated by
     the Azure service processing the request corresponding the event. It in
     ISO 8601 format.
    :vartype event_timestamp: datetime
    :ivar submission_timestamp: the timestamp of when the event became
     available for querying via this API. It is in ISO 8601 format. This value
     should not be confused eventTimestamp. As there might be a delay between
     the occurrence time of the event, and the time that the event is submitted
     to the Azure logging infrastructure.
    :vartype submission_timestamp: datetime
    :ivar subscription_id: the Azure subscription Id usually a GUID.
    :vartype subscription_id: str
    :ivar tenant_id: the Azure tenant Id
    :vartype tenant_id: str
    """

    _validation = {
        'authorization': {'readonly': True},
        'claims': {'readonly': True},
        'caller': {'readonly': True},
        'description': {'readonly': True},
        'id': {'readonly': True},
        'event_data_id': {'readonly': True},
        'correlation_id': {'readonly': True},
        'event_name': {'readonly': True},
        'category': {'readonly': True},
        'http_request': {'readonly': True},
        'level': {'readonly': True},
        'resource_group_name': {'readonly': True},
        'resource_provider_name': {'readonly': True},
        'resource_id': {'readonly': True},
        'resource_type': {'readonly': True},
        'operation_id': {'readonly': True},
        'operation_name': {'readonly': True},
        'properties': {'readonly': True},
        'status': {'readonly': True},
        'sub_status': {'readonly': True},
        'event_timestamp': {'readonly': True},
        'submission_timestamp': {'readonly': True},
        'subscription_id': {'readonly': True},
        'tenant_id': {'readonly': True},
    }

    _attribute_map = {
        'authorization': {'key': 'authorization', 'type': 'SenderAuthorization'},
        'claims': {'key': 'claims', 'type': '{str}'},
        'caller': {'key': 'caller', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'event_data_id': {'key': 'eventDataId', 'type': 'str'},
        'correlation_id': {'key': 'correlationId', 'type': 'str'},
        'event_name': {'key': 'eventName', 'type': 'LocalizableString'},
        'category': {'key': 'category', 'type': 'LocalizableString'},
        'http_request': {'key': 'httpRequest', 'type': 'HttpRequestInfo'},
        'level': {'key': 'level', 'type': 'EventLevel'},
        'resource_group_name': {'key': 'resourceGroupName', 'type': 'str'},
        'resource_provider_name': {'key': 'resourceProviderName', 'type': 'LocalizableString'},
        'resource_id': {'key': 'resourceId', 'type': 'str'},
        'resource_type': {'key': 'resourceType', 'type': 'LocalizableString'},
        'operation_id': {'key': 'operationId', 'type': 'str'},
        'operation_name': {'key': 'operationName', 'type': 'LocalizableString'},
        'properties': {'key': 'properties', 'type': '{str}'},
        'status': {'key': 'status', 'type': 'LocalizableString'},
        'sub_status': {'key': 'subStatus', 'type': 'LocalizableString'},
        'event_timestamp': {'key': 'eventTimestamp', 'type': 'iso-8601'},
        'submission_timestamp': {'key': 'submissionTimestamp', 'type': 'iso-8601'},
        'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
        'tenant_id': {'key': 'tenantId', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(EventData, self).__init__(**kwargs)
        self.authorization = None
        self.claims = None
        self.caller = None
        self.description = None
        self.id = None
        self.event_data_id = None
        self.correlation_id = None
        self.event_name = None
        self.category = None
        self.http_request = None
        self.level = None
        self.resource_group_name = None
        self.resource_provider_name = None
        self.resource_id = None
        self.resource_type = None
        self.operation_id = None
        self.operation_name = None
        self.properties = None
        self.status = None
        self.sub_status = None
        self.event_timestamp = None
        self.submission_timestamp = None
        self.subscription_id = None
        self.tenant_id = None
