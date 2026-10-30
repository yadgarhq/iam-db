"""Two render-time gaps, one file (yaadgaar 347 and 385).

NUMERIC ENV KNOBS (347). A values FILE decodes a number as float64, and sprig's
`quote` prints float64 with `%v`, so 1000000 renders as "1e+06" and the binary
refuses to boot (`--set` yields int64 and renders fine, which is why a `--set`
test cannot see this). Every numeric env knob renders `| int64 | quote`. The five
knobs the schema leaves untyped on purpose (ADR-0847: `database.port`, `maxConnections`,
`engineMaxConnections`, `replicaCount`, `autoscaling.maxReplicas`) get a render check
at the end of `templates/render-checks.yaml`, because `int64` turns the string "abc"
into 0 silently. A string of digits stays valid (`--set-string replicaCount=2`).
`int64` also maps an over-range value without a word (a 20-digit string to 0, a
values-file 1e20 to -9223372036854775808) and parses a leading-zero string as octal
(`0123` to 83, `08` to 0), so the check takes at most 18 digits with no leading zero,
a number below 1e18, and a `database.port` of at most 65535.

EXTERNAL HOST WITH `database.create: true` (385). `templates/mariadb.yaml` names the
MariaDB CR from `database.host`, so an RDS endpoint there renders a CR named after the
endpoint. A render check refuses `create: true` unless `host` is one DNS-1035 label of
at most 52 characters (a Service is named after the CR, and the StatefulSet's pod
revision label is `<name>-<hash of up to 10>`, at most 63).
The red case mutates VALUES, not the template: both sides read one key, so a values
edit is invisible to the contract gate in `test_mariadb.py`.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
CI_VALUES = CHART / "ci" / "values.yaml"
NAME = yaml.safe_load((CHART / "Chart.yaml").read_text())["name"]
SCHEMA = json.loads((CHART / "values.schema.json").read_text())
MARIADB = ("--api-versions", "k8s.mariadb.com/v1alpha1")
KEDA = ("--api-versions", "keda.sh/v1alpha1")
BIG = (1000000, 2147483648)

# (values path, env var). Every numeric env knob the Deployment renders.
KNOBS = [
    (("database", "port"), "DB_PORT"),
    (("database", "maxConnections"), "DB_MAX_CONNECTIONS"),
    (("database", "engineMaxConnections"), "DB_ENGINE_MAX_CONNECTIONS"),
    (("database", "engineOperatorReserve"), "DB_ENGINE_OPERATOR_RESERVE"),
    (("database", "acquireTimeoutSeconds"), "DB_ACQUIRE_TIMEOUT_SECONDS"),
    (("database", "idleTimeoutSeconds"), "DB_IDLE_TIMEOUT_SECONDS"),
    (("database", "maxLifetimeSeconds"), "DB_MAX_LIFETIME_SECONDS"),
    (("database", "migrationLockTimeoutSeconds"), "DB_MIGRATION_LOCK_TIMEOUT_SECONDS"),
    (("replicaCount",), "REPLICAS"),
    (("autoscaling", "maxReplicas"), "REPLICAS"),
    (("server", "limits", "maxConcurrentStreams"), "LISTEN_MAX_CONCURRENT_STREAMS"),
    (("server", "limits", "keepaliveIntervalSeconds"), "LISTEN_KEEPALIVE_INTERVAL_SECS"),
    (("server", "limits", "keepaliveTimeoutSeconds"), "LISTEN_KEEPALIVE_TIMEOUT_SECS"),
    (("server", "limits", "maxHeaderListBytes"), "LISTEN_MAX_HEADER_LIST_BYTES"),
]
# The render check's own domain cap, where the knob has one the schema cannot carry.
RENDER_CAP = {("database", "port"): 65535}
UNTYPED = [
    ("database", "port"),
    ("database", "maxConnections"),
    ("database", "engineMaxConnections"),
    ("replicaCount",),
    ("autoscaling", "maxReplicas"),
]


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    assert binary, "helm is not on PATH; this suite renders the chart (ADR-0650)"
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def render(overlay: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return helm("template", NAME, str(CHART), "-f", str(CI_VALUES), "-f", str(overlay), *extra)


def nest(path: tuple[str, ...], value) -> dict:
    for key in reversed(path):
        value = {key: value}
    return value


def write(tmp_path: Path, body: dict, name: str = "overlay.yaml") -> Path:
    destination = tmp_path / name
    destination.write_text(yaml.safe_dump(body))
    return destination


def env_value(stdout: str, name: str) -> str | None:
    lines = stdout.splitlines()
    return next(
        (lines[i + 1].strip().removeprefix("value: ") for i, line in enumerate(lines) if line.strip() == f"- name: {name}"),
        None,
    )


def schema_maximum(path: tuple[str, ...]) -> int | None:
    node = SCHEMA
    for key in path:
        node = node["properties"][key]
    return node.get("maximum", RENDER_CAP.get(path))


def set_args(path: tuple[str, ...], flag: str, value: str) -> list[str]:
    args = ["template", NAME, str(CHART), "-f", str(CI_VALUES), flag,
            f"{'.'.join(path)}={value}", *extra_for(path)]
    if path[0] == "autoscaling":
        args += ["--set", "autoscaling.enabled=true"]
    return args


def extra_for(path: tuple[str, ...]) -> tuple[str, ...]:
    return KEDA if path[0] == "autoscaling" else ()


def overlay_for(path: tuple[str, ...], value) -> dict:
    body = nest(path, value)
    if path[0] == "autoscaling":
        body["autoscaling"]["enabled"] = True
    if path[-1] == "keepaliveTimeoutSeconds":  # must stay below the interval (render check)
        body["server"]["limits"]["keepaliveIntervalSeconds"] = schema_maximum(
            ("server", "limits", "keepaliveIntervalSeconds")
        )
    return body


@pytest.mark.parametrize("value", BIG)
@pytest.mark.parametrize(("path", "env"), KNOBS, ids=[".".join(p) for p, _ in KNOBS])
def test_a_values_file_number_renders_as_a_plain_decimal(tmp_path, path, env, value):
    """A values FILE (not --set) with 1000000 / 2147483648 renders the decimal string,
    or, where the schema caps the knob, the cap itself."""
    cap = schema_maximum(path)
    wanted = min(value, cap) if cap is not None else value
    result = render(write(tmp_path, overlay_for(path, wanted)), *extra_for(path))
    assert result.returncode == 0, result.stderr
    assert env_value(result.stdout, env) == f'"{wanted}"'


@pytest.mark.parametrize("bad", ["abc", 1.5, -1, True, [1]])
@pytest.mark.parametrize("path", UNTYPED, ids=[".".join(p) for p in UNTYPED])
def test_a_non_integer_in_a_numeric_knob_is_refused_by_name(tmp_path, path, bad):  # noqa: E501
    """`int64` turns "abc" into 0 silently, so the render check must refuse it first."""
    result = render(write(tmp_path, overlay_for(path, bad)), *extra_for(path))
    assert result.returncode != 0, f"{'.'.join(path)}={bad!r} rendered: no refusal"
    assert ".".join(path) in result.stderr, result.stderr


@pytest.mark.parametrize("bad", ["abc", -1])
@pytest.mark.parametrize("path", UNTYPED, ids=[".".join(p) for p in UNTYPED])
def test_set_string_that_is_not_a_whole_number_is_refused(path, bad):
    """`--set-string` (a Go string, not a float) must be refused too, not coerced to 0."""
    args = ["template", NAME, str(CHART), "-f", str(CI_VALUES), "--set-string",
            f"{'.'.join(path)}={bad}", *extra_for(path)]
    if path[0] == "autoscaling":
        args += ["--set", "autoscaling.enabled=true"]
    result = helm(*args)
    assert result.returncode != 0, f"{'.'.join(path)}={bad!r} rendered: no refusal"
    assert ".".join(path) in result.stderr, result.stderr


@pytest.mark.parametrize("path", UNTYPED, ids=[".".join(p) for p in UNTYPED])
def test_set_string_of_digits_still_renders(path):
    """ADR-0847 / yaadgaar 1341: an untyped leaf accepts a string; digits stay valid."""
    wanted = min(1000000, RENDER_CAP.get(path, 1000000))
    result = helm(*set_args(path, "--set-string", str(wanted)))
    assert result.returncode == 0, result.stderr
    env = dict(KNOBS)[path]
    assert env_value(result.stdout, env) == f'"{wanted}"'


# A 20-digit string maps to 0 and a values-file 1e20 to -9223372036854775808 through
# `int64`; a leading zero is read as octal (0123 -> 83, 08 -> 0). Each must be refused.
OVER_RANGE_STRINGS = ["99999999999999999999", "1000000000000000000", "0123", "08"]


@pytest.mark.parametrize("flag", ["--set-string", "--set"])
@pytest.mark.parametrize("bad", OVER_RANGE_STRINGS)
@pytest.mark.parametrize("path", UNTYPED, ids=[".".join(p) for p in UNTYPED])
def test_an_over_range_or_leading_zero_string_is_refused(path, bad, flag):
    result = helm(*set_args(path, flag, bad))
    assert result.returncode != 0, f"{'.'.join(path)}={bad} rendered {env_value(result.stdout, dict(KNOBS)[path])}"
    assert ".".join(path) in result.stderr, result.stderr


@pytest.mark.parametrize("bad", [1e20, 1e18])
@pytest.mark.parametrize("path", UNTYPED, ids=[".".join(p) for p in UNTYPED])
def test_an_over_range_values_file_number_is_refused(tmp_path, path, bad):
    result = render(write(tmp_path, overlay_for(path, bad)), *extra_for(path))
    assert result.returncode != 0, f"{'.'.join(path)}={bad} rendered {env_value(result.stdout, dict(KNOBS)[path])}"
    assert ".".join(path) in result.stderr, result.stderr


@pytest.mark.parametrize("source", ["file", "--set-string"])
def test_a_port_above_65535_is_refused_and_65535_renders(tmp_path, source):
    path = ("database", "port")
    for value, ok in ((65536, False), (65535, True)):
        if source == "file":
            result = render(write(tmp_path, overlay_for(path, value)))
        else:
            result = helm(*set_args(path, "--set-string", str(value)))
        if ok:
            assert result.returncode == 0, result.stderr
            assert env_value(result.stdout, "DB_PORT") == f'"{value}"'
        else:
            assert result.returncode != 0, f"port {value} rendered"
            assert "database.port" in result.stderr and "65535" in result.stderr, result.stderr


# --- 385 ---------------------------------------------------------------------

EXTERNAL = "mydb.abc.eu-west-1.rds.amazonaws.com"
REFUSED_HOSTS = [
    EXTERNAL,
    "UpperCase",
    "under_score",
    "-leading",
    "trailing-",
    "a" * 53,
    "a" * 64,
    "1db",
    "0abc",
    "",
    "has space",
]
ACCEPTED_HOSTS = ["iam-db-mariadb", "a", "a" * 52, "db1"]


@pytest.mark.parametrize("host", REFUSED_HOSTS, ids=lambda h: h[:20] or "empty")
def test_create_true_with_a_host_that_is_not_one_dns_label_is_refused(tmp_path, host):
    overlay = write(tmp_path, {"database": {"host": host, "create": True}})
    result = render(overlay, *MARIADB)
    assert result.returncode != 0, "rendered a MariaDB CR named after the host"
    assert "database.host" in result.stderr
    assert "database.create" in result.stderr
    assert "database.create: false" in result.stderr  # tells the adopter the way out


def test_the_refusal_is_the_host_check_and_not_the_operator_check(tmp_path):
    """With the operator's group present the refusal must be about the host."""
    result = render(write(tmp_path, {"database": {"host": EXTERNAL, "create": True}}), *MARIADB)
    assert "mariadb-operator" not in result.stderr


@pytest.mark.parametrize("host", ACCEPTED_HOSTS, ids=lambda h: h[:20])
def test_create_true_with_one_dns_label_renders_the_cr_named_after_it(tmp_path, host):
    result = render(write(tmp_path, {"database": {"host": host, "create": True}}), *MARIADB)
    assert result.returncode == 0, result.stderr
    kinds = [d for d in yaml.safe_load_all(result.stdout) if d and d.get("kind") == "MariaDB"]
    assert [d["metadata"]["name"] for d in kinds] == [host]


@pytest.mark.parametrize("host", [EXTERNAL, "UpperCase"])
def test_create_false_leaves_an_external_host_alone(tmp_path, host):
    result = render(write(tmp_path, {"database": {"host": host, "create": False}}))
    assert result.returncode == 0, result.stderr
    assert env_value(result.stdout, "DB_HOST") == f'"{host}"'


def test_the_shipped_values_pair_create_false_with_a_label():
    values = yaml.safe_load((CHART / "values.yaml").read_text())["database"]
    assert values["create"] is False
    assert re.fullmatch(r"[a-z]([-a-z0-9]*[a-z0-9])?", values["host"])
    assert len(values["host"]) <= 52
