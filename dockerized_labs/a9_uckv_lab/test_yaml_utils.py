"""Tests for the YAML-loading fix (CWE-502) in a9_uckv_lab.

Run from anywhere with the standard library test runner:

    python -m unittest dockerized_labs/a9_uckv_lab/test_yaml_utils.py

Only PyYAML is required (no Flask/Pillow), because the parsing logic lives in
``yaml_utils.py`` on purpose.

The tests assert two things:
  1. The fix keeps working for legitimate YAML (functional regression guard).
  2. Payloads that exploited the old ``yaml.Loader`` are now refused instead
     of executing (security regression guard).
"""

import io
import os
import sys
import unittest

# Make the module importable regardless of the current working directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import yaml  # noqa: E402
from yaml_utils import parse_yaml  # noqa: E402


class SafeYamlLoadingTests(unittest.TestCase):
    def test_parses_benign_mapping(self):
        data = parse_yaml("name: pygoat\nversion: 1\nitems:\n  - a\n  - b\n")
        self.assertEqual(data, {"name": "pygoat", "version": 1, "items": ["a", "b"]})

    def test_parses_from_bytes_stream(self):
        # The route passes a file-like stream; make sure that still works.
        stream = io.BytesIO(b"key: value\nnested:\n  flag: true\n")
        self.assertEqual(parse_yaml(stream), {"key": "value", "nested": {"flag": True}})

    def test_rejects_python_object_apply(self):
        # Under the old yaml.Loader this executed os.system(...). safe_load must refuse it.
        malicious = "!!python/object/apply:os.system ['echo pwned']"
        with self.assertRaises(yaml.YAMLError):
            parse_yaml(malicious)

    def test_rejects_python_object_new(self):
        malicious = "!!python/object/new:os.system ['id']"
        with self.assertRaises(yaml.YAMLError):
            parse_yaml(malicious)


if __name__ == "__main__":
    unittest.main()
