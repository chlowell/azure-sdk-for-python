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


class SsisObjectMetadataStatusResponse(Model):
    """The status of the operation.

    :param status: The status of the operation.
    :type status: str
    :param name: The operation name.
    :type name: str
    :param properties: The operation properties.
    :type properties: str
    :param error: The operation error message.
    :type error: str
    """

    _attribute_map = {
        'status': {'key': 'status', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'str'},
        'error': {'key': 'error', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(SsisObjectMetadataStatusResponse, self).__init__(**kwargs)
        self.status = kwargs.get('status', None)
        self.name = kwargs.get('name', None)
        self.properties = kwargs.get('properties', None)
        self.error = kwargs.get('error', None)
