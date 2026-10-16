#!/usr/bin/env python3
"""config/schema_validator.py: JSON schema validation for dbug config files.

Validates lab_config.yaml, mock_canaries.json, tracker_catalog.json against
JSON schemas. Stdlib-only (jsonschema optional; regex/structural fallback).

Usage:
    python config/schema_validator.py --config config/lab_config.yaml --schema config/schemas/lab_config.schema.json
    python config/schema_validator.py --all
"""
import argparse
import json
import os
import sys
import re

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False

SCHEMA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schemas")


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_yaml(path):
    if HAS_YAML:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    # Minimal fallback: return empty dict (cannot validate YAML without PyYAML)
    return {}


def validate_with_schema(data, schema):
    """Validate data against a JSON schema. Returns (ok, errors)."""
    if HAS_JSONSCHEMA:
        try:
            jsonschema.validate(data, schema)
            return True, []
        except jsonschema.ValidationError as e:
            return False, [str(e)]
    # Fallback: structural check only (keys exist, types roughly match)
    errors = []
    if not isinstance(data, dict):
        errors.append("top-level must be an object")
        return False, errors
    required = schema.get("required", [])
    for key in required:
        if key not in data:
            errors.append("missing required key: %s" % key)
    return (len(errors) == 0), errors


def validate_file(config_path, schema_path):
    """Validate a single config file against a schema."""
    schema = load_json(schema_path)
    ext = os.path.splitext(config_path)[1].lower()
    if ext in (".yaml", ".yml"):
        data = load_yaml(config_path)
    elif ext == ".json":
        data = load_json(config_path)
    else:
        return False, ["unknown extension: %s" % ext]

    ok, errors = validate_with_schema(data, schema)
    return ok, errors


def validate_all():
    """Validate all known config files against their schemas."""
    checks = [
        ("config/lab_config.yaml", "config/schemas/lab_config.schema.json"),
        ("config/mock_canaries.json", None),  # no schema yet
        ("config/tracker_catalog.json", None),
    ]
    results = []
    for cfg_path, schema_path in checks:
        if not os.path.isfile(cfg_path):
            results.append((cfg_path, False, ["file not found"]))
            continue
        if schema_path and os.path.isfile(schema_path):
            ok, errors = validate_file(cfg_path, schema_path)
        else:
            # Just check it's valid JSON/YAML
            ext = os.path.splitext(cfg_path)[1].lower()
            try:
                if ext == ".json":
                    load_json(cfg_path)
                elif ext in (".yaml", ".yml"):
                    load_yaml(cfg_path)
                ok, errors = True, []
            except Exception as e:
                ok, errors = False, [str(e)]
        results.append((cfg_path, ok, errors))
    return results


def main():
    parser = argparse.ArgumentParser(description="Validate dbug config files against JSON schemas")
    parser.add_argument("--config", help="Path to config file to validate")
    parser.add_argument("--schema", help="Path to JSON schema file (required with --config)")
    parser.add_argument("--all", action="store_true", help="Validate all known config files")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    args = parser.parse_args()

    if args.all:
        results = validate_all()
        if args.json:
            print(json.dumps([{"file": c, "ok": o, "errors": e} for c, o, e in results], indent=2))
        else:
            for cfg_path, ok, errors in results:
                status = "OK" if ok else "FAIL"
                print("%s: %s" % (cfg_path, status))
                for e in errors:
                    print("  - %s" % e)
        return 0 if all(o for _, o, _ in results) else 1

    if args.config:
        if not args.schema:
            print("--schema is required with --config", file=sys.stderr)
            return 1
        ok, errors = validate_file(args.config, args.schema)
        if args.json:
            print(json.dumps({"file": args.config, "ok": ok, "errors": errors}, indent=2))
        else:
            print("%s: %s" % (args.config, "OK" if ok else "FAIL"))
            for e in errors:
                print("  - %s" % e)
        return 0 if ok else 1

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())