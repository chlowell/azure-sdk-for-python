# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import json

try:
    from unittest.mock import Mock
except ImportError:  # python < 3.3
    from mock import Mock  # type: ignore

from requests.structures import CaseInsensitiveDict

from azure_devtools.scenario_tests import json_body_matcher


def assert_match(r1, r2):
    assert json_body_matcher(r1, r2)
    assert json_body_matcher(r2, r1)


def assert_not_match(r1, r2):
    assert not json_body_matcher(r1, r2)
    assert not json_body_matcher(r2, r1)


def mock_request(content, content_type="application/json"):
    return Mock(headers=CaseInsensitiveDict({"content-type": content_type}), body=content)


def test_identical_json():
    content = json.dumps({"a": "b", "c": [1, 2, 3]})
    r1 = mock_request(content)
    r2 = mock_request(content)
    assert_match(r1, r2)


def test_ordering():
    """element ordering should not affect matching"""

    r1 = mock_request('{"a": "b", "c": "d"}')
    r2 = mock_request('{"c": "d", "a": "b"}')
    assert_match(r1, r2)

    r1 = mock_request('{"a": "b", "c": {"d": "e"}}')
    r2 = mock_request('{"c": {"d": "e"}, "a": "b"}')
    assert_match(r1, r2)

    r1 = mock_request('{"a": "b", "c": {"d": ["e", "f"]}}')
    r2 = mock_request('{"c": {"d": ["e", "f"]}, "a": "b"}')
    assert_match(r1, r2)

    r1 = mock_request('{"a": "b", "c": {"d": ["e", [1,2,3]]}}')
    r2 = mock_request('{"c": {"d": ["e", [1,2,3]]}, "a": "b"}')
    assert_match(r1, r2)


def test_different_json():
    content = {"a": [1, 2]}
    r1 = mock_request(json.dumps(content))
    r2 = mock_request(json.dumps(dict(content, b=3)))
    assert_not_match(r1, r2)


def test_not_json():
    """requests not claiming to carry json should match (vacuously)"""

    content = "not json"
    text_plain = "text/plain"
    r1 = mock_request(content, content_type=text_plain)
    r2 = mock_request(content, content_type=text_plain)
    assert_match(r1, r2)

    # even should their content be different
    r1 = mock_request(content, content_type=text_plain)
    r2 = mock_request(content * 2, content_type=text_plain)
    assert_match(r1, r2)

    # even should the content actually be json
    content = json.dumps({1: 2})
    r1 = mock_request(content, content_type=text_plain)
    r2 = mock_request(content, content_type=text_plain)
    assert_match(r1, r2)


def test_invalid_json():
    """requests with invalid json should match iff the content is directly equal"""

    content = '{"a": }'
    r1 = mock_request(content)
    r2 = mock_request(content)
    assert_match(r1, r2)

    r1 = mock_request('{"a": }')
    r2 = mock_request('{"b": }')
    assert_not_match(r1, r2)


def test_only_one_body():
    """if both requests claim json but only one has it, they shouldn't match"""

    r1 = mock_request(None)
    r2 = mock_request(json.dumps({1: 2}))
    assert_not_match(r1, r2)


def test_no_bodies():
    """two requests having no content should match (vacuously)"""

    r1 = mock_request(None, content_type=None)
    r2 = mock_request(None, content_type=None)
    assert_match(r1, r2)

    r1 = mock_request(None)
    r2 = mock_request(None)
    assert_match(r1, r2)
