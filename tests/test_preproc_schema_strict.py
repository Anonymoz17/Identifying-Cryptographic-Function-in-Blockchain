import json
import os
import pytest


def test_schema_file_validates_minimal_metadata():
    # require jsonschema in the environment; skip otherwise (CI should install it)
    pytest.importorskip("jsonschema")

    repo_dir = os.path.dirname(os.path.dirname(__file__))
    schema_path = os.path.join(
        repo_dir, "src", "auditor", "detectors", "static_detection", "schemas", "preproc.metadata.schema.json"
    )
    schema_path = os.path.normpath(schema_path)
    assert os.path.isfile(schema_path), f"schema file missing: {schema_path}"

    with open(schema_path, "r", encoding="utf-8") as fh:
        schema = json.load(fh)

    # Construct minimal valid metadata according to tightened schema: include schema_version and a hex file_hash
    metadata = {"schema_version": "1.0", "file_hash": "a" * 64}

    # Use the project's validator helper (which wraps jsonschema)
    import sys
    # Ensure any test-inserted stub validator is removed so we exercise the
    # real validator implementation when jsonschema is installed.
    sys.modules.pop("auditor.detectors.static_detection.validator", None)
    from auditor.detectors.static_detection import validator

    # Should not raise
    validator.validate_schema(metadata, schema)
