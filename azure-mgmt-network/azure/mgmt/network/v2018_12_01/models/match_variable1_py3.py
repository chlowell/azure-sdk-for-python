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


class MatchVariable1(Model):
    """Define match variables.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Match Variable. Possible values include:
     'RemoteAddr', 'RequestMethod', 'QueryString', 'PostArgs', 'RequestUri',
     'RequestHeaders', 'RequestBody', 'RequestCookies'
    :type name: str or ~azure.mgmt.network.v2018_12_01.models.MatchVariable
    :param selector: Describes field of the matchVariable collection
    :type selector: str
    """

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'selector': {'key': 'selector', 'type': 'str'},
    }

    def __init__(self, *, name, selector: str=None, **kwargs) -> None:
        super(MatchVariable1, self).__init__(**kwargs)
        self.name = name
        self.selector = selector
