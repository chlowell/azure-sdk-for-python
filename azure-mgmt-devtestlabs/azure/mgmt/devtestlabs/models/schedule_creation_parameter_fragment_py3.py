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


class ScheduleCreationParameterFragment(Model):
    """Properties for creating a schedule.

    :param status: The status of the schedule (i.e. Enabled, Disabled).
     Possible values include: 'Enabled', 'Disabled'
    :type status: str or ~azure.mgmt.devtestlabs.models.EnableStatus
    :param task_type: The task type of the schedule (e.g. LabVmsShutdownTask,
     LabVmAutoStart).
    :type task_type: str
    :param weekly_recurrence: If the schedule will occur only some days of the
     week, specify the weekly recurrence.
    :type weekly_recurrence:
     ~azure.mgmt.devtestlabs.models.WeekDetailsFragment
    :param daily_recurrence: If the schedule will occur once each day of the
     week, specify the daily recurrence.
    :type daily_recurrence: ~azure.mgmt.devtestlabs.models.DayDetailsFragment
    :param hourly_recurrence: If the schedule will occur multiple times a day,
     specify the hourly recurrence.
    :type hourly_recurrence:
     ~azure.mgmt.devtestlabs.models.HourDetailsFragment
    :param time_zone_id: The time zone ID (e.g. Pacific Standard time).
    :type time_zone_id: str
    :param notification_settings: Notification settings.
    :type notification_settings:
     ~azure.mgmt.devtestlabs.models.NotificationSettingsFragment
    :param target_resource_id: The resource ID to which the schedule belongs
    :type target_resource_id: str
    :param name: The name of the virtual machine or environment
    :type name: str
    :param location: The location of the new virtual machine or environment
    :type location: str
    :param tags: The tags of the resource.
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'status': {'key': 'properties.status', 'type': 'str'},
        'task_type': {'key': 'properties.taskType', 'type': 'str'},
        'weekly_recurrence': {'key': 'properties.weeklyRecurrence', 'type': 'WeekDetailsFragment'},
        'daily_recurrence': {'key': 'properties.dailyRecurrence', 'type': 'DayDetailsFragment'},
        'hourly_recurrence': {'key': 'properties.hourlyRecurrence', 'type': 'HourDetailsFragment'},
        'time_zone_id': {'key': 'properties.timeZoneId', 'type': 'str'},
        'notification_settings': {'key': 'properties.notificationSettings', 'type': 'NotificationSettingsFragment'},
        'target_resource_id': {'key': 'properties.targetResourceId', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, *, status=None, task_type: str=None, weekly_recurrence=None, daily_recurrence=None, hourly_recurrence=None, time_zone_id: str=None, notification_settings=None, target_resource_id: str=None, name: str=None, location: str=None, tags=None, **kwargs) -> None:
        super(ScheduleCreationParameterFragment, self).__init__(**kwargs)
        self.status = status
        self.task_type = task_type
        self.weekly_recurrence = weekly_recurrence
        self.daily_recurrence = daily_recurrence
        self.hourly_recurrence = hourly_recurrence
        self.time_zone_id = time_zone_id
        self.notification_settings = notification_settings
        self.target_resource_id = target_resource_id
        self.name = name
        self.location = location
        self.tags = tags
