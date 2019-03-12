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


class Action(Model):
    """Action descriptor.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: AlertingAction, LogToMetricAction

    All required parameters must be populated in order to send to Azure.

    :param odatatype: Required. Constant filled by server.
    :type odatatype: str
    """

    _validation = {
        'odatatype': {'required': True},
    }

    _attribute_map = {
        'odatatype': {'key': 'odata\\.type', 'type': 'str'},
    }

    _subtype_map = {
        'odatatype': {'Microsoft.WindowsAzure.Management.Monitoring.Alerts.Models.Microsoft.AppInsights.Nexus.DataContracts.Resources.ScheduledQueryRules.AlertingAction': 'AlertingAction', 'Microsoft.WindowsAzure.Management.Monitoring.Alerts.Models.Microsoft.AppInsights.Nexus.DataContracts.Resources.ScheduledQueryRules.LogToMetricAction': 'LogToMetricAction'}
    }

    def __init__(self, **kwargs):
        super(Action, self).__init__(**kwargs)
        self.odatatype = None
