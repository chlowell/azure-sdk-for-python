# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
from azure.core.exceptions import DecodeError
from azure.core.pipeline import PipelineResponse
from azure.core.polling.base_polling import BadResponse, LongRunningOperation, LROBasePolling, OperationFailed, OperationResourcePolling


class KeyVaultBackupClientPolling(OperationResourcePolling):
    def __init__(self):
        super(KeyVaultBackupClientPolling, self).__init__(operation_location_header="azure-asyncoperation")

    def get_final_get_url(self, pipeline_response):
        return None

    # def can_poll(self, pipeline_response):
    #     type: (Union[PipelineResponse, BackupOperation, RestoreOperation]) -> bool
        # if isinstance(pipeline_response, PipelineResponse):
        #     return super(KeyVaultBackupClientPolling, self).can_poll(pipeline_response)
        # return True


class BackupClientLRO(LongRunningOperation):
    def __init__(self, initial_response):
        self._url = initial_response.http_request.url

    def can_poll(self, pipeline_response):
        return True

    def get_polling_url(self):
        return self._url

    def set_initial_status(self, pipeline_response):
        if pipeline_response.http_response.status_code in {200, 201, 202, 204}:
            return "InProgress"
        raise OperationFailed("Operation failed or canceled")

    def get_status(self, pipeline_response):
        text = pipeline_response.http_response.text()
        try:
            body = json.loads(pipeline_response.http_response.text())
        except ValueError:
            raise DecodeError("Error occurred in deserializing the response body.")

        status = body.get("status")
        if not status:
            raise BadResponse("No status found in body")

        return status

    def get_final_get_url(self, pipeline_response):
        return None


class PollingMethod(LROBasePolling):
    # def initialize(self, client, initial_response, deserialization_callback):
    #     pass

    # def from_continuation_token(cls, continuation_token, **kwargs):
    #     # LROPoller is caller, expects (client, initial_response, deserialization_callback).
    #     # client and deserialization_callback are in kwargs, so this method need only contribute initial_response.
    #     # LROPoller doesn't use initial_response, only passes it back to this class's .initialize()
    #     return super().from_continuation_token(continuation_token, **kwargs)

    def get_continuation_token(self):
        return self.resource().id
