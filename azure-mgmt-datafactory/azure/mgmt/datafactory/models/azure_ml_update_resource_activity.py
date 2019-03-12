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


class AzureMLUpdateResourceActivity(ExecutionActivity):
    """Azure ML Update Resource management activity.

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
    :param trained_model_name: Required. Name of the Trained Model module in
     the Web Service experiment to be updated. Type: string (or Expression with
     resultType string).
    :type trained_model_name: object
    :param trained_model_linked_service_name: Required. Name of Azure Storage
     linked service holding the .ilearner file that will be uploaded by the
     update operation.
    :type trained_model_linked_service_name:
     ~azure.mgmt.datafactory.models.LinkedServiceReference
    :param trained_model_file_path: Required. The relative file path in
     trainedModelLinkedService to represent the .ilearner file that will be
     uploaded by the update operation.  Type: string (or Expression with
     resultType string).
    :type trained_model_file_path: object
    """

    _validation = {
        'name': {'required': True},
        'type': {'required': True},
        'trained_model_name': {'required': True},
        'trained_model_linked_service_name': {'required': True},
        'trained_model_file_path': {'required': True},
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
        'trained_model_name': {'key': 'typeProperties.trainedModelName', 'type': 'object'},
        'trained_model_linked_service_name': {'key': 'typeProperties.trainedModelLinkedServiceName', 'type': 'LinkedServiceReference'},
        'trained_model_file_path': {'key': 'typeProperties.trainedModelFilePath', 'type': 'object'},
    }

    def __init__(self, **kwargs):
        super(AzureMLUpdateResourceActivity, self).__init__(**kwargs)
        self.trained_model_name = kwargs.get('trained_model_name', None)
        self.trained_model_linked_service_name = kwargs.get('trained_model_linked_service_name', None)
        self.trained_model_file_path = kwargs.get('trained_model_file_path', None)
        self.type = 'AzureMLUpdateResource'
