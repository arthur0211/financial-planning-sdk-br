"""Closed stdlib validator for the four JSON Schemas bundled by this SDK.

This is deliberately not a general JSON Schema implementation.  It recognizes
only the Draft 2020-12 keywords, local references, formats, and patterns used by
the packaged contracts and rejects schema drift outside that reviewed subset.
"""

from __future__ import annotations

import re
from datetime import date
from typing import TypeAlias, cast

from .jsonio import JsonObject, JsonValue

_Schema: TypeAlias = bool | dict[str, JsonValue]

_DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"
_JSON_TYPES = frozenset({"array", "boolean", "integer", "null", "object", "string"})
_SUPPORTED_FORMATS = frozenset({"date"})
_LOCAL_DEFINITION_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*\Z", re.ASCII)
_SUPPORTED_KEYWORDS = frozenset(
    {
        "$defs",
        "$id",
        "$ref",
        "$schema",
        "additionalProperties",
        "allOf",
        "anyOf",
        "const",
        "contains",
        "else",
        "enum",
        "format",
        "if",
        "items",
        "maxContains",
        "maximum",
        "maxItems",
        "maxLength",
        "minContains",
        "minimum",
        "minItems",
        "minLength",
        "not",
        "oneOf",
        "pattern",
        "prefixItems",
        "properties",
        "required",
        "then",
        "title",
        "type",
        "uniqueItems",
        "x-significant-digit-budget",
    }
)

# Exact inventory after the absolute-end guard is added to every full-string
# pattern.  New patterns require explicit review instead of silently relying on
# Python ``re`` for an unexamined ECMA-262 construct.
SUPPORTED_PATTERNS = frozenset(
    {
        r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]{1,18})?$(?![\s\S])",
        r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]{1,20})?$(?![\s\S])",
        r"^-?(?:0|[1-9][0-9]*)\.[0-9]{2}$(?![\s\S])",
        r"^(?:|/(?:[ -}]|~[01])*)$(?![\s\S])",
        r"^(?:|/(?:[A-Za-z0-9_.~-]+)(?:/[A-Za-z0-9_.~-]+)*)$(?![\s\S])",
        r"^(?:|/cases(?:/[0-9]+)?)$(?![\s\S])",
        r"^[ -~]+$(?![\s\S])",
        r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$(?![\s\S])",
        r"^[0-9a-f]{64}$(?![\s\S])",
        r"^[a-z][a-z0-9_-]{0,63}$(?![\s\S])",
        r"^[a-z][a-z0-9_.-]{0,127}$(?![\s\S])",
        r"^/",
        r"^/(?:case_roster(?:/[0-9]+)?|cases(?:/[0-2]/case_id)?)$(?![\s\S])",
        r"^/cases/[0-2]/(?:expected_output(?:_sha256)?|assertions(?:/(?:[0-9]|1[0-5])(?:/(?:assertion_id|rule_id|json_pointer|expected))?)?)$(?![\s\S])",
        r"^/cases/[0-2]/derivation_id$(?![\s\S])",
        r"^/cases/[0-2]/operation$(?![\s\S])",
        r"^/cases/[0-2]/request(?:/use_context)?$(?![\s\S])",
    }
)


class ClosedSchemaError(ValueError):
    """The packaged schema moved outside the reviewed stdlib subset."""


class SchemaInstanceError(ValueError):
    """An instance did not satisfy its complete packaged public schema."""


def _exact_int(value: object) -> bool:
    return type(value) is int


def _schema_object(value: object, *, context: str) -> dict[str, JsonValue]:
    if type(value) is not dict:
        raise ClosedSchemaError(f"{context} must be one exact JSON object")
    return cast(dict[str, JsonValue], value)


def _schema_list(value: object, *, context: str) -> list[JsonValue]:
    if type(value) is not list:
        raise ClosedSchemaError(f"{context} must be one exact JSON array")
    return cast(list[JsonValue], value)


def _non_negative_integer(value: object, *, context: str) -> int:
    if not _exact_int(value) or cast(int, value) < 0:
        raise ClosedSchemaError(f"{context} must be one non-negative integer")
    return cast(int, value)


def _definition_name(value: object, *, context: str) -> str:
    if type(value) is not str or _LOCAL_DEFINITION_NAME.fullmatch(value) is None:
        raise ClosedSchemaError(f"{context} is outside the closed ASCII definition-name grammar")
    return value


def _local_reference_name(reference: object) -> str:
    if type(reference) is not str or not reference.startswith("#/$defs/"):
        raise ClosedSchemaError("only direct local $defs references are supported")
    name = _definition_name(reference.removeprefix("#/$defs/"), context="local reference token")
    if reference != f"#/$defs/{name}":
        raise ClosedSchemaError("local reference is outside the closed direct-$defs form")
    return name


def _resolve_local_reference(root: JsonObject, reference: object) -> _Schema:
    name = _local_reference_name(reference)
    definitions = _schema_object(root.get("$defs"), context="$defs")
    if name not in definitions:
        raise ClosedSchemaError("local reference does not resolve inside the packaged schema")
    target = definitions[name]
    if type(target) is bool:
        return target
    return _schema_object(target, context=f"$defs/{name}")


def _check_schema_node(
    node: object,
    root: JsonObject,
    *,
    context: str,
    root_node: bool,
) -> None:
    if type(node) is bool:
        return
    schema = _schema_object(node, context=context)
    unknown = set(schema) - _SUPPORTED_KEYWORDS
    if unknown:
        raise ClosedSchemaError(f"unsupported JSON Schema keyword(s): {sorted(unknown)!r}")

    if not root_node and ("$schema" in schema or "$id" in schema):
        raise ClosedSchemaError("$schema and $id are supported only at the schema root")
    if not root_node and "$defs" in schema:
        raise ClosedSchemaError("$defs is supported only at the root of the closed direct-reference profile")
    if "$schema" in schema and schema["$schema"] != _DRAFT_2020_12:
        raise ClosedSchemaError("only the declared Draft 2020-12 dialect is supported")
    for annotation in ("$id", "title"):
        if annotation in schema and type(schema[annotation]) is not str:
            raise ClosedSchemaError(f"{annotation} must be one string")

    if "$ref" in schema:
        _resolve_local_reference(root, schema["$ref"])

    if "type" in schema and (type(schema["type"]) is not str or schema["type"] not in _JSON_TYPES):
        raise ClosedSchemaError("type is outside the closed packaged vocabulary")
    if "enum" in schema and not _schema_list(schema["enum"], context=f"{context}/enum"):
        raise ClosedSchemaError("enum must contain at least one JSON value")
    if "required" in schema:
        required = _schema_list(schema["required"], context=f"{context}/required")
        if any(type(name) is not str for name in required) or len(set(cast(list[str], required))) != len(required):
            raise ClosedSchemaError("required must contain unique strings")

    for keyword in ("minimum", "maximum"):
        if keyword in schema and not _exact_int(schema[keyword]):
            raise ClosedSchemaError(f"{keyword} must be one exact integer in this subset")
    for keyword in ("minItems", "maxItems", "minLength", "maxLength", "minContains", "maxContains"):
        if keyword in schema:
            _non_negative_integer(schema[keyword], context=f"{context}/{keyword}")
    if "uniqueItems" in schema and type(schema["uniqueItems"]) is not bool:
        raise ClosedSchemaError("uniqueItems must be one boolean")
    if ("minContains" in schema or "maxContains" in schema) and "contains" not in schema:
        raise ClosedSchemaError("contains bounds without contains are unsupported")
    if "minContains" in schema and "maxContains" in schema:
        if cast(int, schema["minContains"]) > cast(int, schema["maxContains"]):
            raise ClosedSchemaError("minContains cannot exceed maxContains")

    if "pattern" in schema:
        pattern = schema["pattern"]
        if type(pattern) is not str or pattern not in SUPPORTED_PATTERNS:
            raise ClosedSchemaError("pattern is outside the closed reviewed inventory")
        try:
            re.compile(pattern)
        except re.error as exc:  # pragma: no cover - inventory literals are compiled in tests
            raise ClosedSchemaError("pattern cannot be compiled by the reviewed runtime") from exc
    if "format" in schema:
        value = schema["format"]
        if type(value) is not str or value not in _SUPPORTED_FORMATS:
            raise ClosedSchemaError("format is outside the closed packaged vocabulary")
    if "x-significant-digit-budget" in schema:
        budget = schema["x-significant-digit-budget"]
        if not _exact_int(budget) or cast(int, budget) < 1:
            raise ClosedSchemaError("x-significant-digit-budget must be one positive integer")

    for mapping_keyword in ("$defs", "properties"):
        if mapping_keyword in schema:
            mapping = _schema_object(schema[mapping_keyword], context=f"{context}/{mapping_keyword}")
            for name, child in mapping.items():
                if type(name) is not str:
                    raise ClosedSchemaError(f"{context}/{mapping_keyword} names must be strings")
                if mapping_keyword == "$defs":
                    _definition_name(name, context=f"{context}/$defs name")
                _check_schema_node(
                    child,
                    root,
                    context=f"{context}/{mapping_keyword}/{name}",
                    root_node=False,
                )
    for array_keyword in ("allOf", "anyOf", "oneOf", "prefixItems"):
        if array_keyword in schema:
            children = _schema_list(schema[array_keyword], context=f"{context}/{array_keyword}")
            if array_keyword != "prefixItems" and not children:
                raise ClosedSchemaError(f"{array_keyword} must contain at least one schema")
            for index, child in enumerate(children):
                _check_schema_node(
                    child,
                    root,
                    context=f"{context}/{array_keyword}/{index}",
                    root_node=False,
                )
    for schema_keyword in ("additionalProperties", "contains", "else", "if", "items", "not", "then"):
        if schema_keyword in schema:
            _check_schema_node(
                schema[schema_keyword],
                root,
                context=f"{context}/{schema_keyword}",
                root_node=False,
            )
    if ("then" in schema or "else" in schema) and "if" not in schema:
        raise ClosedSchemaError("then/else without if is outside the closed subset")


def _collect_local_references(node: _Schema) -> set[str]:
    if type(node) is bool:
        return set()
    references: set[str] = set()
    if "$ref" in node:
        references.add(_local_reference_name(node["$ref"]))
    if "properties" in node:
        mapping = _schema_object(node["properties"], context="properties")
        for child in mapping.values():
            references.update(_collect_local_references(cast(_Schema, child)))
    for array_keyword in ("allOf", "anyOf", "oneOf", "prefixItems"):
        if array_keyword in node:
            children = _schema_list(node[array_keyword], context=array_keyword)
            for child in children:
                references.update(_collect_local_references(cast(_Schema, child)))
    for schema_keyword in ("additionalProperties", "contains", "else", "if", "items", "not", "then"):
        if schema_keyword in node:
            references.update(_collect_local_references(cast(_Schema, node[schema_keyword])))
    return references


def _assert_acyclic_local_references(root: JsonObject) -> None:
    raw_definitions = root.get("$defs", {})
    definitions = _schema_object(raw_definitions, context="$defs")
    graph: dict[tuple[str, str], set[tuple[str, str]]] = {
        ("root", ""): {("definition", name) for name in _collect_local_references(root)}
    }
    for name, target in definitions.items():
        checked_name = _definition_name(name, context="$defs name")
        graph[("definition", checked_name)] = {
            ("definition", referenced)
            for referenced in _collect_local_references(cast(_Schema, target))
        }

    active: set[tuple[str, str]] = set()
    complete: set[tuple[str, str]] = set()

    def visit(vertex: tuple[str, str]) -> None:
        if vertex in active:
            raise ClosedSchemaError("cyclic local $ref topology is outside the closed profile")
        if vertex in complete:
            return
        if vertex not in graph:
            raise ClosedSchemaError("local reference does not resolve inside the packaged schema")
        active.add(vertex)
        for target in graph[vertex]:
            visit(target)
        active.remove(vertex)
        complete.add(vertex)

    for vertex in graph:
        visit(vertex)


def _assert_closed_schema(schema: JsonObject, *, expected_id: str | None) -> None:
    if schema.get("$schema") != _DRAFT_2020_12:
        raise ClosedSchemaError("packaged schema dialect is inconsistent")
    if expected_id is not None and schema.get("$id") != expected_id:
        raise ClosedSchemaError("packaged schema identity is inconsistent")
    _check_schema_node(schema, schema, context="#", root_node=True)
    _assert_acyclic_local_references(schema)


def assert_supported_schema(schema: JsonObject, *, expected_id: str) -> None:
    try:
        root = _schema_object(schema, context="#")
        _assert_closed_schema(root, expected_id=expected_id)
    except RecursionError as exc:
        raise ClosedSchemaError("schema recursion exceeds the closed profile") from exc


def _json_equal(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if type(left) is list:
        left_list = cast(list[object], left)
        right_list = cast(list[object], right)
        return len(left_list) == len(right_list) and all(
            _json_equal(left_item, right_item) for left_item, right_item in zip(left_list, right_list, strict=True)
        )
    if type(left) is dict:
        left_dict = cast(dict[str, object], left)
        right_dict = cast(dict[str, object], right)
        return left_dict.keys() == right_dict.keys() and all(
            _json_equal(left_dict[key], right_dict[key]) for key in left_dict
        )
    return left == right


def _type_matches(instance: object, expected: str) -> bool:
    return {
        "array": type(instance) is list,
        "boolean": type(instance) is bool,
        "integer": type(instance) is int,
        "null": instance is None,
        "object": type(instance) is dict,
        "string": type(instance) is str,
    }[expected]


def _valid_date(value: str) -> bool:
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        return False
    return parsed.isoformat() == value


def _significant_digits(value: str) -> int:
    digits = value.lstrip("-").replace(".", "").lstrip("0")
    return len(digits) or 1


def _matches(node: _Schema, instance: object, root: JsonObject) -> bool:
    if type(node) is bool:
        return node
    schema = node

    if "$ref" in schema and not _matches(_resolve_local_reference(root, schema["$ref"]), instance, root):
        return False
    if "type" in schema and not _type_matches(instance, cast(str, schema["type"])):
        return False
    if "const" in schema and not _json_equal(instance, schema["const"]):
        return False
    if "enum" in schema and not any(
        _json_equal(instance, candidate) for candidate in cast(list[JsonValue], schema["enum"])
    ):
        return False

    if type(instance) is dict:
        document = cast(dict[str, object], instance)
        if "required" in schema and any(name not in document for name in cast(list[str], schema["required"])):
            return False
        properties = cast(dict[str, JsonValue], schema.get("properties", {}))
        for name, child_schema in properties.items():
            if name in document and not _matches(cast(_Schema, child_schema), document[name], root):
                return False
        if "additionalProperties" in schema:
            additional = cast(_Schema, schema["additionalProperties"])
            for name in document.keys() - properties.keys():
                if not _matches(additional, document[name], root):
                    return False

    if type(instance) is list:
        items = cast(list[object], instance)
        if "minItems" in schema and len(items) < cast(int, schema["minItems"]):
            return False
        if "maxItems" in schema and len(items) > cast(int, schema["maxItems"]):
            return False
        prefix = cast(list[JsonValue], schema.get("prefixItems", []))
        for index, child_schema in enumerate(prefix[: len(items)]):
            if not _matches(cast(_Schema, child_schema), items[index], root):
                return False
        if "items" in schema:
            item_schema = cast(_Schema, schema["items"])
            if any(not _matches(item_schema, item, root) for item in items[len(prefix) :]):
                return False
        if schema.get("uniqueItems") is True:
            for index, item in enumerate(items):
                if any(_json_equal(item, candidate) for candidate in items[index + 1 :]):
                    return False
        if "contains" in schema:
            contains_schema = cast(_Schema, schema["contains"])
            count = sum(_matches(contains_schema, item, root) for item in items)
            minimum = cast(int, schema.get("minContains", 1))
            maximum = cast(int | None, schema.get("maxContains"))
            if count < minimum or (maximum is not None and count > maximum):
                return False

    if type(instance) is str:
        text = instance
        if "minLength" in schema and len(text) < cast(int, schema["minLength"]):
            return False
        if "maxLength" in schema and len(text) > cast(int, schema["maxLength"]):
            return False
        if "pattern" in schema and re.search(cast(str, schema["pattern"]), text) is None:
            return False
        if schema.get("format") == "date" and not _valid_date(text):
            return False
        if "x-significant-digit-budget" in schema:
            if _significant_digits(text) > cast(int, schema["x-significant-digit-budget"]):
                return False

    if type(instance) is int:
        integer = instance
        if "minimum" in schema and integer < cast(int, schema["minimum"]):
            return False
        if "maximum" in schema and integer > cast(int, schema["maximum"]):
            return False

    if "allOf" in schema and not all(
        _matches(cast(_Schema, child), instance, root) for child in cast(list[JsonValue], schema["allOf"])
    ):
        return False
    if "anyOf" in schema and not any(
        _matches(cast(_Schema, child), instance, root) for child in cast(list[JsonValue], schema["anyOf"])
    ):
        return False
    if "oneOf" in schema:
        match_count = sum(
            _matches(cast(_Schema, child), instance, root) for child in cast(list[JsonValue], schema["oneOf"])
        )
        if match_count != 1:
            return False
    if "not" in schema and _matches(cast(_Schema, schema["not"]), instance, root):
        return False
    if "if" in schema:
        condition = _matches(cast(_Schema, schema["if"]), instance, root)
        branch = "then" if condition else "else"
        if branch in schema and not _matches(cast(_Schema, schema[branch]), instance, root):
            return False
    return True


def assert_schema_instance(schema: JsonObject, instance: object, *, fragment: str | None = None) -> None:
    try:
        root = _schema_object(schema, context="#")
        _assert_closed_schema(root, expected_id=None)
        node: _Schema = root if fragment is None else _resolve_local_reference(root, fragment)
    except RecursionError as exc:
        raise ClosedSchemaError("schema recursion exceeds the closed profile") from exc
    try:
        matches = _matches(node, instance, root)
    except RecursionError as exc:
        raise SchemaInstanceError("instance recursion exceeds the closed validation budget") from exc
    if not matches:
        raise SchemaInstanceError("value does not satisfy the complete packaged public schema")
