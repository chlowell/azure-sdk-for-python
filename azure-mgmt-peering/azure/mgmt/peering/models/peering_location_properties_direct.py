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


class PeeringLocationPropertiesDirect(Model):
    """The properties that define a direct peering location.

    :param peering_facilities: The list of direct peering facilities at the
     peering location.
    :type peering_facilities:
     list[~azure.mgmt.peering.models.DirectPeeringFacility]
    :param bandwidth_offers: The list of bandwidth offers avaiable at the
     peering location.
    :type bandwidth_offers:
     list[~azure.mgmt.peering.models.PeeringBandwidthOffer]
    """

    _attribute_map = {
        'peering_facilities': {'key': 'peeringFacilities', 'type': '[DirectPeeringFacility]'},
        'bandwidth_offers': {'key': 'bandwidthOffers', 'type': '[PeeringBandwidthOffer]'},
    }

    def __init__(self, **kwargs):
        super(PeeringLocationPropertiesDirect, self).__init__(**kwargs)
        self.peering_facilities = kwargs.get('peering_facilities', None)
        self.bandwidth_offers = kwargs.get('bandwidth_offers', None)
