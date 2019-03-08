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


class ContactInfo(Model):
    """The contact information of the peer.

    :param emails: The list of email addresses.
    :type emails: list[str]
    :param phone: The list of contact numbers.
    :type phone: list[str]
    """

    _attribute_map = {
        'emails': {'key': 'emails', 'type': '[str]'},
        'phone': {'key': 'phone', 'type': '[str]'},
    }

    def __init__(self, *, emails=None, phone=None, **kwargs) -> None:
        super(ContactInfo, self).__init__(**kwargs)
        self.emails = emails
        self.phone = phone
