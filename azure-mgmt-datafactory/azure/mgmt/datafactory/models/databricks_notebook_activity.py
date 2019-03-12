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

from .execution_activity import ExecutionActivity


class DatabricksNotebookActivity(ExecutionActivity):
    """DatabricksNotebook activity.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param name: Required. Activity name.
    :type name: str
    :param description: Activity description.
    :type description: str
    :param depends_on: Activity depends on condition.
    :type depends_on: list[~azure.mgmt.datafactory.models.ActivityDependency]
    :param user_properties: Activity user properties.
    :type user_properties: list[~azure.mgmt.datafactory.models.UserProperty]
    :param type: Required. Constant filled by server.
    :type type: str
    :param linked_service_name: Linked service reference.
    :type linked_service_name:
     ~azure.mgmt.datafactory.models.LinkedServiceReference
    :param policy: Activity policy.
    :type policy: ~azure.mgmt.datafactory.models.ActivityPolicy
    :param notebook_path: Required. The absolute path of the notebook to be
     run in the Databricks Workspace. This path must begin with a slash. Type:
     string (or Expression with resultType string).
    :type notebook_path: object
    :param base_parameters: Base parameters to be used for each run of this
     job.If the notebook takes a parameter that is not specified, the default
     value from the notebook will be used.
    :type base_parameters: dict[str, object]
    :param libraries: A list of libraries to be installed on the cluster that
     will execute the job.
    :type libraries: list[dict[str, object]]
    """

    _validation = {
        'name': {'required': True},
        'type': {'required': True},
        'notebook_path': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'name': {'key': 'name', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'depends_on': {'key': 'dependsOn', 'type': '[ActivityDependency]'},
        'user_properties': {'key': 'userProperties', 'type': '[UserProperty]'},
        'type': {'key': 'type', 'type': 'str'},
        'linked_service_name': {'key': 'linkedServiceName', 'type': 'LinkedServiceReference'},
        'policy': {'key': 'policy', 'type': 'ActivityPolicy'},
        'notebook_path': {'key': 'typeProperties.notebookPath', 'type': 'object'},
        'base_parameters': {'key': 'typeProperties.baseParameters', 'type': '{object}'},
        'libraries': {'key': 'typeProperties.libraries', 'type': '[{object}]'},
    }

    def __init__(self, **kwargs):
        super(DatabricksNotebookActivity, self).__init__(**kwargs)
        self.notebook_path = kwargs.get('notebook_path', None)
        self.base_parameters = kwargs.get('base_parameters', None)
        self.libraries = kwargs.get('libraries', None)
        self.type = 'DatabricksNotebook'
