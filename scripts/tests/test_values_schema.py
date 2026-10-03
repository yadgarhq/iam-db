"""The closed `values.schema.json` (ledger 990, ADR-0847, ADR-0850).

Until this file the chart's schema bounded exactly one knob
(`database.migrationLockTimeoutSeconds`, ledger 814 — see
`test_migration_lock_schema.py`, unchanged by this file) and validated
nothing else: any other typo in `values.yaml` rendered cleanly and reached
the pod, or the service, as whatever was actually written. This file closes
every object the chart's own `values.yaml` declares, so an unknown key is
refused AT RENDER, before anything is applied.

CLOSURE IS PER CHART (ADR-0850). This schema closes only the keys iam-db
owns. `global` stays an open map here on purpose: a parent or platform chart
that embeds iam-db injects it into the coalesced values whether or not this
chart reads it, and a closed root would refuse that injection the moment
iam-db is vendored into one.

TYPES, TOGGLES AND `required` ON A NEW KEY ARE NOT THIS SCHEMA'S JOB
(ADR-0847). `chart/templates/render-checks.yaml` already refuses a non-bool
`database.create` or `autoscaling.enabled`, an absent one, and a non-map
`autoscaling`, each with its own named sentence — this suite asserts the
schema stays OUT of that lane (the "render-check, not schema" rows below) as
carefully as it asserts the schema's own refusals. The two typed leaves that
predate this closure (`database.migrationLockTimeoutSeconds`,
`database`'s own `type: object` + `required`) are kept unchanged and are
`test_migration_lock_schema.py`'s territory, not re-asserted here except
where a shipped-behaviour row needs them for contrast.

NEVER ASSERT HELM'S OWN WORDING. `additionalProperties: false` is reported
differently by helm 3.18.4 (`- <path>: Additional property X is not
allowed`) and by 3.20.2 / 4.3.0 (`- at '/<path>': additional properties 'X'
not allowed`) — both measured. Every RED assertion below checks the key name
and the path fragment, never the connecting sentence.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml

CHART = Path(__file__).resolve().parents[2] / "chart"
SCHEMA_PATH = CHART / "values.schema.json"

# Paths the schema leaves open (declared as a bare `{}`), though `values.yaml`
# either nests real structure under them or omits them outright. §3.4 of the
# D-S brief.
OPEN = {"global", "resources", "rollingUpdate", "database.instance.resources"}

# Paths the schema declares as leaves though `values.yaml` never states them —
# a template reads each one and no mapping in `values.yaml` owns it. §2 step 2,
# §3.6 of the D-S brief.
EXTRAS = {"image.digest", "networkPolicy.scrapeFrom.namespace"}


def load_schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text())


def load_values() -> dict[str, Any]:
    return yaml.safe_load((CHART / "values.yaml").read_text()) or {}


# --------------------------------------------------------------------------
# PURE structural checks — no helm invoked. Each returns a list of failures so
# a mutation test can assert the SAME function catches the defect it names.
# --------------------------------------------------------------------------


def closure_failures(schema: dict[str, Any]) -> list[str]:
    """Every object with `properties` is closed, unless its path is OPEN; every
    OPEN path stays a bare `{}` rather than growing nested properties."""
    failures: list[str] = []

    def walk(node: Any, path: str) -> None:
        if not isinstance(node, dict):
            failures.append(f"{path or '(root)'}: schema node is not an object")
            return
        if "properties" in node:
            if path in OPEN:
                failures.append(f"{path}: declared open but carries nested 'properties'")
            elif node.get("additionalProperties") is not False:
                failures.append(f"{path or '(root)'}: has 'properties' but additionalProperties is not false")
            for name, sub in node["properties"].items():
                walk(sub, f"{path}.{name}" if path else name)
        elif path in OPEN and node != {}:
            failures.append(f"{path}: declared open but is not a bare {{}} node")

    walk(schema, "")
    return failures


def schema_leaf_paths(schema: dict[str, Any]) -> set[str]:
    """Every path reachable in the schema that is NOT a `properties` block —
    a plain leaf, an open map, or an extra — excluding the root itself."""
    leaves: set[str] = set()

    def walk(node: Any, path: str) -> None:
        if not isinstance(node, dict):
            return
        if "properties" in node:
            for name, sub in node["properties"].items():
                walk(sub, f"{path}.{name}" if path else name)
        elif path:
            leaves.add(path)

    walk(schema, "")
    return leaves


def values_leaf_paths(values: dict[str, Any]) -> set[str]:
    """Every leaf path in values.yaml, stopping recursion at an OPEN path (the
    schema declares no structure past that boundary, so neither does this
    walk)."""
    leaves: set[str] = set()

    def walk(node: Any, path: str) -> None:
        if path in OPEN:
            leaves.add(path)
            return
        if isinstance(node, dict) and node:
            for name, sub in node.items():
                walk(sub, f"{path}.{name}" if path else name)
        elif isinstance(node, dict):
            # an EMPTY mapping (e.g. `networkPolicy.scrapeFrom: {}`). A leaf,
            # UNLESS an EXTRA nests under it — then §3.6 makes it a CLOSED
            # BLOCK in the schema instead, with no leaf of its own here.
            if not any(e == path or e.startswith(f"{path}.") for e in EXTRAS):
                leaves.add(path)
        else:
            # a leaf: a scalar, a list, or null
            leaves.add(path)

    for key, val in values.items():
        walk(val, key)
    return leaves


def undeclared_value_failures(schema: dict[str, Any], values: dict[str, Any]) -> list[str]:
    """Every values.yaml leaf path must be declared somewhere in the schema."""
    declared = schema_leaf_paths(schema)
    return [f"{p}: in values.yaml, not declared in the schema" for p in sorted(values_leaf_paths(values) - declared)]


def extras_mismatch_failures(schema: dict[str, Any], values: dict[str, Any]) -> list[str]:
    """Every schema leaf absent from values.yaml (and not `global`, which is
    its own check below) must be exactly the EXTRAS tuple — no more, no
    fewer."""
    extra_in_schema = schema_leaf_paths(schema) - values_leaf_paths(values) - {"global"}
    failures = []
    for missing in sorted(EXTRAS - extra_in_schema):
        failures.append(f"{missing}: expected as an extra, not declared in the schema")
    for unexpected in sorted(extra_in_schema - EXTRAS):
        failures.append(f"{unexpected}: declared in the schema, in neither values.yaml nor the EXTRAS tuple")
    return failures


def global_failures(schema: dict[str, Any]) -> list[str]:
    if schema.get("properties", {}).get("global") != {}:
        return ["global: not declared as an open map ({}) at the root"]
    return []


def test_every_object_is_closed_unless_declared_open() -> None:
    failures = closure_failures(load_schema())
    assert not failures, failures


def test_every_values_yaml_leaf_is_declared() -> None:
    failures = undeclared_value_failures(load_schema(), load_values())
    assert not failures, failures


def test_every_extra_is_declared_and_nothing_else_is() -> None:
    failures = extras_mismatch_failures(load_schema(), load_values())
    assert not failures, failures


def test_global_is_declared_open() -> None:
    failures = global_failures(load_schema())
    assert not failures, failures


# --------------------------------------------------------------------------
# Mutation checks — each breaks ONE property the checks above assert, then
# asserts the SAME function reddens. A structural suite that cannot fail
# proves nothing (the sibling suites' "measures what it claims to" pattern).
# --------------------------------------------------------------------------


def test_deleting_root_additional_properties_reddens_the_closure_check() -> None:
    mutated = copy.deepcopy(load_schema())
    del mutated["additionalProperties"]
    assert closure_failures(mutated), "deleting the root's additionalProperties should have reddened"


def test_deleting_global_reddens_the_global_check() -> None:
    mutated = copy.deepcopy(load_schema())
    del mutated["properties"]["global"]
    assert global_failures(mutated), "deleting `global` should have reddened"


def test_deleting_an_extra_reddens_the_extras_check() -> None:
    mutated = copy.deepcopy(load_schema())
    del mutated["properties"]["image"]["properties"]["digest"]
    assert extras_mismatch_failures(mutated, load_values()), "deleting `image.digest` should have reddened"


def test_closing_an_open_map_reddens_the_closure_check() -> None:
    mutated = copy.deepcopy(load_schema())
    mutated["properties"]["resources"] = {"properties": {}, "additionalProperties": False}
    assert closure_failures(mutated), "closing `resources` should have reddened"


# --------------------------------------------------------------------------
# Render-based checks — the ADR-0645 sweep's red/green table (§5).
# --------------------------------------------------------------------------


def helm_binaries() -> list[str]:
    found = []
    for name in ("helm",):
        binary = shutil.which(name)
        assert binary, (
            "helm is not on PATH. This suite renders the chart, and so does the "
            "`helm lint and render` pre-commit hook — install helm rather than skip."
        )
        found.append(binary)
    return found


def render(binary: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([binary, "template", "x", str(CHART), *arguments], capture_output=True, text=True)


def values_file(tmp_path: Path, name: str, body: Any) -> str:
    path = tmp_path / f"{name}.yaml"
    path.write_text(body if isinstance(body, str) else yaml.safe_dump(body))
    return str(path)


def objects(stdout: str) -> int:
    return sum(1 for doc in yaml.safe_load_all(stdout) if isinstance(doc, dict) and doc.get("apiVersion"))


def test_defaults_still_render_unchanged() -> None:
    for binary in helm_binaries():
        result = render(binary)
        assert result.returncode == 0, result.stderr
        assert objects(result.stdout) == 4, result.stdout


def test_lint_strict_passes_on_defaults() -> None:
    for name in ("helm",):
        binary = shutil.which(name)
        result = subprocess.run([binary, "lint", "--strict", str(CHART)], capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr


def test_root_typo_is_refused_naming_the_key_and_the_root_path(tmp_path: Path) -> None:
    for binary in helm_binaries():
        result = render(binary, "-f", values_file(tmp_path, "r1", {"databse": {"create": True}}))
        assert result.returncode != 0, "a root-level typo rendered"
        assert "databse" in result.stderr, result.stderr


def test_lint_strict_refuses_the_root_typo_naming_the_key(tmp_path: Path) -> None:
    overlay = values_file(tmp_path, "lint-r1", {"databse": {"create": True}})
    for name in ("helm",):
        binary = shutil.which(name)
        result = subprocess.run(
            [binary, "lint", "--strict", str(CHART), "-f", overlay], capture_output=True, text=True
        )
        assert result.returncode != 0, "lint --strict passed a root-level typo"
        assert "databse" in (result.stdout + result.stderr)


def test_one_down_typo_is_refused_naming_the_key_under_its_parent(tmp_path: Path) -> None:
    for binary in helm_binaries():
        result = render(binary, "-f", values_file(tmp_path, "r2", {"database": {"creat": True}}))
        assert result.returncode != 0, "a nested typo rendered"
        assert "creat" in result.stderr, result.stderr
        assert "database" in result.stderr, result.stderr


def test_two_down_typo_is_refused_naming_the_key_under_its_path(tmp_path: Path) -> None:
    overlay = {"database": {"instance": {"storage": {"siz": "1Gi"}}}}
    for binary in helm_binaries():
        result = render(binary, "-f", values_file(tmp_path, "r3", overlay))
        assert result.returncode != 0, "a two-levels-down typo rendered"
        assert "siz" in result.stderr, result.stderr
        assert "storage" in result.stderr, result.stderr


def test_shipped_database_scalar_is_still_a_schema_type_refusal(tmp_path: Path) -> None:
    """`database: "x"` is refused by the schema's retained `type: object` on
    `database` — shipped behaviour, unchanged by this closure."""
    for binary in helm_binaries():
        result = render(binary, "-f", values_file(tmp_path, "t1", {"database": "x"}))
        assert result.returncode != 0, "a scalar `database` rendered"
        assert "database" in result.stderr, result.stderr


def test_deleted_database_is_a_render_check_sentence_not_a_schema_line(tmp_path: Path) -> None:
    overlay = "database:\n"
    for binary in helm_binaries():
        result = render(binary, "-f", values_file(tmp_path, "t2", overlay))
        assert result.returncode != 0
        assert "is absent from the values" in result.stderr, result.stderr


def test_database_create_quoted_false_is_a_render_check_sentence_not_a_schema_line(tmp_path: Path) -> None:
    """The schema does not type `database.create`; `render-checks.yaml`'s own
    `kindIs "bool"` arm (D-M, ledger 1135) is what refuses this, and it must
    keep doing so with the schema in place."""
    for binary in helm_binaries():
        result = render(binary, "-f", values_file(tmp_path, "t3", {"database": {"create": "false"}}))
        assert result.returncode != 0, "a quoted-string database.create rendered a MariaDB"
        assert "must be true or false" in result.stderr, result.stderr


def test_database_create_deleted_is_a_render_check_sentence(tmp_path: Path) -> None:
    overlay = "database:\n  create:\n"
    for binary in helm_binaries():
        result = render(binary, "-f", values_file(tmp_path, "t4", overlay))
        assert result.returncode != 0
        assert "`database.create` is absent" in result.stderr, result.stderr


def test_migration_lock_timeout_null_is_still_a_schema_required_refusal(tmp_path: Path) -> None:
    overlay = "database:\n  migrationLockTimeoutSeconds:\n"
    for binary in helm_binaries():
        result = render(binary, "-f", values_file(tmp_path, "t5", overlay))
        assert result.returncode != 0, "a nulled migrationLockTimeoutSeconds rendered"
        assert "migrationLockTimeoutSeconds" in result.stderr, result.stderr


def test_open_resources_map_passes(tmp_path: Path) -> None:
    overlay = {"resources": {"foo": {"bar": 1}}}
    for binary in helm_binaries():
        result = render(binary, "-f", values_file(tmp_path, "o1", overlay))
        assert result.returncode == 0, result.stderr
        assert objects(result.stdout) == 4


def test_open_global_map_passes(tmp_path: Path) -> None:
    overlay = {"global": {"whatever": 1}}
    for binary in helm_binaries():
        result = render(binary, "-f", values_file(tmp_path, "o2", overlay))
        assert result.returncode == 0, result.stderr
        assert objects(result.stdout) == 4


def test_open_rolling_update_passes(tmp_path: Path) -> None:
    overlay = {"rollingUpdate": {"partition": 1}}
    for binary in helm_binaries():
        result = render(binary, "-f", values_file(tmp_path, "o3", overlay))
        assert result.returncode == 0, result.stderr
        assert objects(result.stdout) == 4


def test_open_database_instance_resources_passes(tmp_path: Path) -> None:
    overlay = {"database": {"instance": {"resources": {"x": {"y": 1}}}}}
    for binary in helm_binaries():
        result = render(binary, "-f", values_file(tmp_path, "o4", overlay))
        assert result.returncode == 0, result.stderr
        assert objects(result.stdout) == 4


def test_extra_image_digest_passes(tmp_path: Path) -> None:
    overlay = {"image": {"digest": "sha256:" + "a" * 64}}
    for binary in helm_binaries():
        result = render(binary, "-f", values_file(tmp_path, "o5", overlay))
        assert result.returncode == 0, result.stderr
        assert objects(result.stdout) == 4


def test_untyped_leaf_accepts_a_string_set(tmp_path: Path) -> None:
    for binary in helm_binaries():
        result = render(binary, "--set-string", "replicaCount=2")
        assert result.returncode == 0, result.stderr
        assert objects(result.stdout) == 4


def test_autoscaling_enabled_quoted_false_is_a_render_check_sentence_not_a_schema_line(tmp_path: Path) -> None:
    """Needs the KEDA API registered or the render check never reaches the
    toggle (its own `hasKey`/`kindIs "map"` guards run first, but the
    `require-api` check downstream needs the capability for the green twin of
    this row; this row is the RED one and refuses before that point)."""
    overlay = {"autoscaling": {"enabled": "false"}}
    for binary in helm_binaries():
        result = render(binary, "--api-versions", "keda.sh/v1alpha1", "-f", values_file(tmp_path, "o6", overlay))
        assert result.returncode != 0, "a quoted-string autoscaling.enabled rendered a ScaledObject"
        assert "must be true or false" in result.stderr, result.stderr
