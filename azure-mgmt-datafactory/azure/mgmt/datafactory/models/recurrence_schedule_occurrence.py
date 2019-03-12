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


class RecurrenceScheduleOccurrence(Model):
    """The recurrence schedule occurrence.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param day: The day of the week. Possible values include: 'Sunday',
     'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'
    :type day: str or ~azure.mgmt.datafactory.models.DayOfWeek
    :param occurrence: The occurrence.
    :type occurrence: int
    """

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'day': {'key': 'day', 'type': 'DayOfWeek'},
        'occurrence': {'key': 'occurrence', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(RecurrenceScheduleOccurrence, self).__init__(**kwargs)
        self.additional_properties = kwargs.get('additional_properties', None)
        self.day = kwargs.get('day', None)
        self.occurrence = kwargs.get('occurrence', None)
