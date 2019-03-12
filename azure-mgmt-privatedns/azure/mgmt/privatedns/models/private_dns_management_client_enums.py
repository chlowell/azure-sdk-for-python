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

from enum import Enum


class ProvisioningState(str, Enum):

    creating = "Creating"
    updating = "Updating"
    deleting = "Deleting"
    succeeded = "Succeeded"
    failed = "Failed"
    canceled = "Canceled"


class VirtualNetworkLinkState(str, Enum):

    in_progress = "InProgress"
    completed = "Completed"


class RecordType(str, Enum):

    a = "A"
    aaaa = "AAAA"
    cname = "CNAME"
    mx = "MX"
    ptr = "PTR"
    soa = "SOA"
    srv = "SRV"
    txt = "TXT"
