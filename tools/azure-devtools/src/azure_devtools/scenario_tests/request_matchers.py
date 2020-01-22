# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import json

import six


class JsonBodyMatcher(object):
    """Tests whether two vcr.py requests have a JSON content type and identical bodies.

    Because vcr.py considers two requests matching iff all matchers return True, this matcher must return vacuous truth
    in some cases. By default, two requests are considered not to match iff they both claim to carry JSON content and
    have content that is either not directly equal, or that deserializes to unequal dicts. The requirement that content
    deserialize to equal dicts can be relaxed with the ``match_attributes_only`` keyword argument.

    :keyword bool match_attributes_only: If ``True``, two JSON objects with identical attributes are considered
     matching regardless of the values of those attributes. Defaults to ``False``.
    """

    def __init__(self, match_attributes_only=False):
        self._match_attributes_only = match_attributes_only

    __name__ = 'JsonBodyMatcher'

    def __call__(self, r1, r2):  # pylint:disable=too-many-return-statements
        if not (r1.body or r2.body):
            # neither request has a body -> vacuous satisfaction
            return True

        # this matcher examines only requests which claim to have json content
        if "json" not in r1.headers.get("Content-Type", "") or "json" not in r2.headers.get("Content-Type", ""):
            # at least one request does not claim json content -> vacuous satisfaction
            # (we leave headers to another matcher)
            return True

        if not (r1.body and r2.body):
            # both requests claim json content but only one has a body
            return False

        if r1.body == r2.body:
            # identical bytestrings deserialize to identical objects
            return True

        # making the simplifying assumption that both bodies are utf-8
        try:
            c1 = json.loads(six.ensure_str(r1.body))
            c2 = json.loads(six.ensure_str(r2.body))
            if self._match_attributes_only:
                return sorted(c1.keys()) == sorted(c2.keys())
            return c1 == c2
        except ValueError:
            # one request carries invalid json not identical to the other's
            return False
