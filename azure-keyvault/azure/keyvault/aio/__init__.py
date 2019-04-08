# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

from .secrets._client import SecretClient
from ..secrets._models import Secret, SecretAttributes, DeletedSecret, SecretAttributesPaged

__all__ = ['SecretClient',
           'SecretAttributes',
           'Secret',
           'SecretAttributesPaged',
           'DeletedSecret']
