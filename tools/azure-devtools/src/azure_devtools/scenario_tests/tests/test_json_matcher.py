# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import json

try:
    from unittest.mock import Mock
except ImportError:  # python < 3.3
    from mock import Mock  # type: ignore

from azure_devtools.scenario_tests import json_attribute_matcher
import pytest
from requests.structures import CaseInsensitiveDict


def assert_match(r1, r2):
    assert json_attribute_matcher(r1, r2)
    assert json_attribute_matcher(r2, r1)


def assert_not_match(r1, r2):
    assert not json_attribute_matcher(r1, r2)
    assert not json_attribute_matcher(r2, r1)


def mock_request(content, content_type="application/json"):
    return Mock(headers=CaseInsensitiveDict({"content-type": content_type}), body=content)


def test_name():
    """vcr.py expects matchers have __name__ set"""

    assert json_attribute_matcher.__name__


def test_identical_json():
    content = json.dumps({"a": "b", "c": [1, 2, 3]})
    r1 = mock_request(content)
    r2 = mock_request(content)
    assert_match(r1, r2)


def test_ordering():
    """attribute ordering should not affect matching"""

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


def test_different_attributes():
    content = {"a": [1, 2, 3]}
    r1 = mock_request(json.dumps(content))
    r2 = mock_request(json.dumps(dict(content, b=3)))
    assert_not_match(r1, r2)


def test_same_attributes_different_values():
    num_list = list(range(3))
    r1 = mock_request(json.dumps({"a": num_list}))
    r2 = mock_request(json.dumps({"a": num_list[::-1]}))
    assert_match(r1, r2)

    r1 = mock_request(json.dumps({1: "a", 2: "b"}))
    r2 = mock_request(json.dumps({1: "c", 2: "d"}))
    assert_match(r1, r2)


def test_not_json():
    """requests not claiming to carry json should match (vacuously) regardless of content"""

    content = "not json"
    text_plain = "text/plain"
    r1 = mock_request(content, content_type=text_plain)
    r2 = mock_request(content, content_type=text_plain)
    assert_match(r1, r2)

    # even should their content be different
    r1 = mock_request(content, content_type=text_plain)
    r2 = mock_request(content * 2, content_type=text_plain)
    assert_match(r1, r2)

    # or identical json
    content = json.dumps({1: 2})
    r1 = mock_request(content, content_type=text_plain)
    r2 = mock_request(content, content_type=text_plain)
    assert_match(r1, r2)

    # or identical invalid json
    content = "{1: 2"
    r1 = mock_request(content, content_type=text_plain)
    r2 = mock_request(content, content_type=text_plain)
    assert_match(r1, r2)


def test_invalid_json():
    """requests with invalid json should match iff the content is directly equal"""

    content = '{"a": }'
    r1 = mock_request(content)
    r2 = mock_request(content)
    assert_match(r1, r2)

    r1 = mock_request(content)
    r2 = mock_request('{"b": }')
    assert_not_match(r1, r2)


def test_only_one_body():
    """if two requests claim json but only one has it, they shouldn't match"""

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
