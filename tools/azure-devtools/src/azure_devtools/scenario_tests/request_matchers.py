# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import json

import six


def json_attribute_matcher(r1, r2):  # pylint:disable=too-many-return-statements
    """Tests whether two vcr.py requests have JSON content with identical attributes (values are ignored).

    Because vcr.py considers two requests matching iff all matchers return ``True``, this matcher returns vacuous truth
    in some cases. Two requests are considered not to match iff they both claim to carry JSON content and their
    content deserializes to dicts with different keys.
    """
    if not (r1.body or r2.body):
        # neither request has a body -> vacuous satisfaction
        return True

    if "json" not in r1.headers.get("Content-Type", "") or "json" not in r2.headers.get("Content-Type", ""):
        # at least one request does not claim json content -> vacuous satisfaction
        # (we leave headers to another matcher)
        return True

    if not (r1.body and r2.body):
        # both requests claim json content but only one has a body
        return False

    if r1.body == r2.body:
        # identical bytestrings deserialize to identical objects, and we consider identical invalid json matching
        return True

    try:
        c1 = json.loads(six.ensure_str(r1.body))
        c2 = json.loads(six.ensure_str(r2.body))
        return sorted(c1.keys()) == sorted(c2.keys())
    except ValueError:
        # one request carries invalid json not identical to the other's
        return False
