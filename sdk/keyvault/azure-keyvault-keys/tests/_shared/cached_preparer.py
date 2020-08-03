# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
from devtools_testutils import CachedKeyVaultPreparer, CachedResourceGroupPreparer


def cached_resource_test(client_preparer, test_fn):
    def wrapper(test_class_instance):
        return CachedResourceGroupPreparer()(CachedKeyVaultPreparer()(client_preparer()(test_fn)))(test_class_instance)

    return wrapper
