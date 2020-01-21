# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import json

import six


def json_body_matcher(r1, r2):
    """Test whether r1 and r2 have a JSON content type and identical bodies.

    Two requests are considered not to match iff they both claim to carry JSON content and have content that is either
    not directly equal, or that deserializes to unequal dicts. Because vcr.py considers two requests matching iff all
    matchers return True, this matcher must return vacuous truth in some cases.
    """

    if not (r1.body or r2.body):
        # neither request has a body -> vacuous satisfaction
        return True

    if "json" not in r1.headers.get("Content-Type", "") or "json" not in r2.headers.get("Content-Type", ""):
        # at least one request does not claim json content -> vacuous satisfaction
        # (we leave headers to another matcher)
        return True

    if not (r1.body and r2.body):
        # one request has a body, the other does not
        return False

    if r1.body == r2.body:
        # identical bytestrings deserialize to identical objects
        return True

    # making the simplifying assumption that both bodies are utf-8
    try:
        c1 = json.loads(six.ensure_str(r1.body))
        c2 = json.loads(six.ensure_str(r2.body))
        return c1 == c2
    except ValueError:
        # one request carries invalid json not identical to the other request's
        return False
