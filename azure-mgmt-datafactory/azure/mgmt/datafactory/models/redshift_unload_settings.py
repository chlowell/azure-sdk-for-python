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


class RedshiftUnloadSettings(Model):
    """The Amazon S3 settings needed for the interim Amazon S3 when copying from
    Amazon Redshift with unload. With this, data from Amazon Redshift source
    will be unloaded into S3 first and then copied into the targeted sink from
    the interim S3.

    All required parameters must be populated in order to send to Azure.

    :param s3_linked_service_name: Required. The name of the Amazon S3 linked
     service which will be used for the unload operation when copying from the
     Amazon Redshift source.
    :type s3_linked_service_name:
     ~azure.mgmt.datafactory.models.LinkedServiceReference
    :param bucket_name: Required. The bucket of the interim Amazon S3 which
     will be used to store the unloaded data from Amazon Redshift source. The
     bucket must be in the same region as the Amazon Redshift source. Type:
     string (or Expression with resultType string).
    :type bucket_name: object
    """

    _validation = {
        's3_linked_service_name': {'required': True},
        'bucket_name': {'required': True},
    }

    _attribute_map = {
        's3_linked_service_name': {'key': 's3LinkedServiceName', 'type': 'LinkedServiceReference'},
        'bucket_name': {'key': 'bucketName', 'type': 'object'},
    }

    def __init__(self, **kwargs):
        super(RedshiftUnloadSettings, self).__init__(**kwargs)
        self.s3_linked_service_name = kwargs.get('s3_linked_service_name', None)
        self.bucket_name = kwargs.get('bucket_name', None)
