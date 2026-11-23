"""Safe YAML parsing for the a9_uckv_lab upload feature.

Security background (CWE-502, Deserialization of Untrusted Data)
----------------------------------------------------------------
The uploader used to call ``yaml.load(stream, Loader=yaml.Loader)``.
``yaml.Loader`` is PyYAML's *full* loader: it honours tags such as
``!!python/object/apply`` and ``!!python/object/new``, which let a YAML
document construct arbitrary Python objects. An attacker who can upload a
YAML file therefore achieves remote code execution on the server.

``yaml.safe_load`` resolves only the standard YAML scalar/sequence/mapping
types, so the very same input is parsed as inert data and the dangerous tags
raise a ``yaml.YAMLError`` instead of executing. The fix is in the *code*
(which loader is called), not in the PyYAML version.
"""

import yaml


def parse_yaml(stream):
    """Parse a YAML document from *stream* (str, bytes, or file-like).

    Uses the safe loader, so only plain data structures are produced. Input
    that tries to instantiate Python objects raises ``yaml.YAMLError`` rather
    than running arbitrary code.
    """
    return yaml.safe_load(stream)
