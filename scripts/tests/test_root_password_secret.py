"""THE MARIADB INSTANCE BLOCK AND ITS ROOT-PASSWORD SECRET NAME (yaadgaar #595).

Behind `database.create`, `templates/render-checks.yaml` refuses a missing, null or non-map
`database.instance`, and a `database.instance.rootPasswordSecret` that is missing, null,
not a string, empty or not a DNS-1123 subdomain, each by key and cause. Before it, the
first died with a bare template trace and the second rendered
`rootPasswordSecretKeyRef.name:` blank. The schema leaves both keys untyped, so every case
is run twice: with the schema, and with `--skip-schema-validation`, where an arm the schema
already precedes stays as the floor (ADR-1150).

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

from pathlib import Path

import pytest

from test_render_checks import (
    CHART,
    DATABASE_TOGGLE_ON,
    MARIADB_API_VERSIONS,
    RAISE_MARKERS,
    objects,
    render,
)

SCHEMA_MODES = ("", "--skip-schema-validation")

# THE APP ACCOUNT READS `instance.rootPasswordSecret` TOO (render-checks.yaml, "must differ from"),
# and only with `database.createAppAccount` on. Every refusal below runs with it off and on, so
# the named refusal must come BEFORE that read, not only at the shipped default.
ACCOUNT_MODES = ((), ("--set", "database.createAppAccount=true"))
ACCOUNT_IDS = ("account-off", "account-on")

# (label, the `database:` block lines under it, the sentence the refusal must carry).
# One row per arm: the needle is distinct per arm, so a mutant that removes an arm lets
# the case fall to another message or a raw error and fails here.
REFUSED = [
    ("instance-null", "instance: ~", "`database.instance` is absent"),
    ("instance-string", "instance: x", "`database.instance` must be a map"),
    ("instance-list", "instance: []", "`database.instance` must be a map"),
    ("root-null", "instance: {rootPasswordSecret: ~}", "`database.instance.rootPasswordSecret` is absent"),
    ("root-number", "instance: {rootPasswordSecret: 5}", "`database.instance.rootPasswordSecret` must be a string"),
    ("root-list", "instance: {rootPasswordSecret: [a]}", "`database.instance.rootPasswordSecret` must be a string"),
    ("root-empty", "instance: {rootPasswordSecret: ''}", "`database.instance.rootPasswordSecret` is empty"),
    ("root-upper", "instance: {rootPasswordSecret: Bad_Name}", "`database.instance.rootPasswordSecret` must be a DNS-1123 subdomain"),
    ("root-space", "instance: {rootPasswordSecret: ' a'}", "`database.instance.rootPasswordSecret` must be a DNS-1123 subdomain"),
    ("root-dash-end", "instance: {rootPasswordSecret: a-}", "`database.instance.rootPasswordSecret` must be a DNS-1123 subdomain"),
    ("root-underscore", "instance: {rootPasswordSecret: a_b}", "`database.instance.rootPasswordSecret` must be a DNS-1123 subdomain"),
    ("root-double-dot", "instance: {rootPasswordSecret: a..b}", "`database.instance.rootPasswordSecret` must be a DNS-1123 subdomain"),
    ("root-too-long", "instance: {rootPasswordSecret: " + "a" * 254 + "}", "`database.instance.rootPasswordSecret` must be a DNS-1123 subdomain"),
]


def overlay(tmp_path: Path, block: str) -> tuple[str, str]:
    path = tmp_path / "overlay.yaml"
    path.write_text(f"database:\n  {block}\n")
    return "-f", str(path)


@pytest.mark.parametrize("account", ACCOUNT_MODES, ids=ACCOUNT_IDS)
@pytest.mark.parametrize("schema", SCHEMA_MODES, ids=("schema", "skip-schema"))
@pytest.mark.parametrize("label, block, sentence", REFUSED, ids=[row[0] for row in REFUSED])
def test_a_bad_instance_block_is_refused_by_key_and_cause(
    tmp_path: Path, account: tuple, schema: str, label: str, block: str, sentence: str
) -> None:
    flags = (schema,) if schema else ()
    result = render(
        CHART, *DATABASE_TOGGLE_ON, *account, *MARIADB_API_VERSIONS, *overlay(tmp_path, block), *flags
    )
    assert result.returncode != 0, f"{label} rendered"
    assert sentence in result.stderr, result.stderr
    for marker in RAISE_MARKERS:
        assert marker not in result.stderr, result.stderr


@pytest.mark.parametrize("account", ACCOUNT_MODES, ids=ACCOUNT_IDS)
@pytest.mark.parametrize("schema", SCHEMA_MODES, ids=("schema", "skip-schema"))
def test_a_set_null_root_secret_is_refused_not_rendered_blank(account: tuple, schema: str) -> None:
    flags = (schema,) if schema else ()
    result = render(
        CHART, *DATABASE_TOGGLE_ON, *account, *MARIADB_API_VERSIONS,
        "--set", "database.instance.rootPasswordSecret=null", *flags,
    )
    assert result.returncode != 0, "a null rootPasswordSecret rendered"
    assert "`database.instance.rootPasswordSecret` is absent" in result.stderr, result.stderr


@pytest.mark.parametrize("account", ACCOUNT_MODES, ids=ACCOUNT_IDS)
@pytest.mark.parametrize("schema", SCHEMA_MODES, ids=("schema", "skip-schema"))
def test_a_set_null_instance_is_refused_not_a_nil_pointer(account: tuple, schema: str) -> None:
    flags = (schema,) if schema else ()
    result = render(
        CHART, *DATABASE_TOGGLE_ON, *account, *MARIADB_API_VERSIONS,
        "--set", "database.instance=null", *flags,
    )
    assert result.returncode != 0, "a null instance rendered"
    assert "`database.instance` is absent" in result.stderr, result.stderr
    for marker in RAISE_MARKERS:
        assert marker not in result.stderr, result.stderr


@pytest.mark.parametrize("account", ACCOUNT_MODES, ids=ACCOUNT_IDS)
@pytest.mark.parametrize(
    "name", ["a", "custom-root", "custom-root.secret1", "0a", "a" * 253], ids=lambda n: n[:12]
)
def test_a_valid_root_secret_name_renders_exactly_as_written(account: tuple, name: str) -> None:
    result = render(
        CHART, *DATABASE_TOGGLE_ON, *account, *MARIADB_API_VERSIONS,
        "--set-string", f"database.instance.rootPasswordSecret={name}",
    )
    assert result.returncode == 0, result.stderr
    [mariadb] = [d for d in objects(result.stdout) if d["kind"] == "MariaDB"]
    assert mariadb["spec"]["rootPasswordSecretKeyRef"]["name"] == name


def test_the_arms_sit_behind_database_create() -> None:
    """With `database.create` false nothing renders the instance, so a bad block is not this
    arm's business: the chart renders, as it did before."""
    for overlay_args in (("--set", "database.instance=null"), ("--set", "database.instance.rootPasswordSecret=null")):
        result = render(CHART, "--set", "database.create=false", *overlay_args)
        assert result.returncode == 0, result.stderr


def test_the_shipped_defaults_render_the_shipped_root_secret_name() -> None:
    result = render(CHART, *DATABASE_TOGGLE_ON, *MARIADB_API_VERSIONS)
    assert result.returncode == 0, result.stderr
    [mariadb] = [d for d in objects(result.stdout) if d["kind"] == "MariaDB"]
    assert mariadb["spec"]["rootPasswordSecretKeyRef"]["name"] == "iam-db-mariadb-root"
    assert render(CHART).returncode == 0
