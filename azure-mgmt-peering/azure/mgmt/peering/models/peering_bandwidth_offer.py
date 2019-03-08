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


class PeeringBandwidthOffer(Model):
    """The properties that define a peering bandwidth offer.

    :param offer_name: The name of the bandwidth offer.
    :type offer_name: str
    :param value_in_mbps: The value of the bandwidth offer in Mbps.
    :type value_in_mbps: int
    """

    _attribute_map = {
        'offer_name': {'key': 'offerName', 'type': 'str'},
        'value_in_mbps': {'key': 'valueInMbps', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(PeeringBandwidthOffer, self).__init__(**kwargs)
        self.offer_name = kwargs.get('offer_name', None)
        self.value_in_mbps = kwargs.get('value_in_mbps', None)
