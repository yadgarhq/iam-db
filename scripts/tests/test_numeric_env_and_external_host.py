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
RENDER_CAP = {
    ("database", "port"): 65535,
    ("replicaCount",): 2147483647,
    ("autoscaling", "maxReplicas"): 2147483647,
}
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


# --- 482 ---------------------------------------------------------------------
# UNQUOTED numeric renders print a values-file float64 as `1e+06` (the apiserver
# refuses a float for an int32 field), the replica knobs had no upper bound, port 0
# passed.

INT32_MAX = 2147483647  # the int32 field Kubernetes stores a replica count in
REPLICA_KNOBS = [
    (("replicaCount",), "Deployment", ("spec", "replicas")),
    (("autoscaling", "minReplicas"), "ScaledObject", ("spec", "minReplicaCount")),
    (("autoscaling", "maxReplicas"), "ScaledObject", ("spec", "maxReplicaCount")),
    (("database", "instance", "replicas"), "MariaDB", ("spec", "replicas")),
]
API = (*KEDA, *MARIADB)


def replica_overlay(path: tuple[str, ...], value) -> dict:
    body = nest(path, value)
    if path[0] == "autoscaling":
        body["autoscaling"]["enabled"] = True
    if path == ("autoscaling", "minReplicas"):
        body["autoscaling"]["maxReplicas"] = INT32_MAX  # 645: the ceiling may not sit below the floor
    if path[0] == "database":
        body["database"]["create"] = True
    return body


def rendered_field(stdout: str, kind: str, field: tuple[str, ...]):
    documents = [d for d in yaml.safe_load_all(stdout) if d and d.get("kind") == kind]
    assert len(documents) == 1, f"{kind}: expected one document, found {len(documents)}"
    node = documents[0]
    for key in field:
        node = node[key]
    return node


REPLICA_IDS = [".".join(p) for p, _, _ in REPLICA_KNOBS]


@pytest.mark.parametrize("value", [1000000, INT32_MAX])
@pytest.mark.parametrize(("path", "kind", "field"), REPLICA_KNOBS, ids=REPLICA_IDS)
def test_a_replica_count_from_a_values_file_renders_as_an_integer(tmp_path, path, kind, field, value):
    """`replicas: {{ .Values.replicaCount }}` printed a float64 as `1e+06`."""
    result = render(write(tmp_path, replica_overlay(path, value)), *API)
    assert result.returncode == 0, result.stderr
    got = rendered_field(result.stdout, kind, field)
    assert got == value and isinstance(got, int), f"{'.'.join(path)}={value} rendered {got!r}"


@pytest.mark.parametrize("source", ["file", "--set-string"])
@pytest.mark.parametrize(("path", "kind", "field"), REPLICA_KNOBS, ids=REPLICA_IDS)
def test_a_replica_count_above_int32_is_refused_and_int32_max_renders(tmp_path, path, kind, field, source):
    """MAX + 1 refused naming the key, MAX accepted (the int32 apiserver field)."""
    for value, ok in ((INT32_MAX + 1, False), (INT32_MAX, True)):
        if source == "file":
            result = render(write(tmp_path, replica_overlay(path, value)), *API)
        else:
            args = ["template", NAME, str(CHART), "-f", str(CI_VALUES), "--set-string",
                    f"{'.'.join(path)}={value}", *API]
            if path[0] == "autoscaling":
                args += ["--set", "autoscaling.enabled=true"]
            if path == ("autoscaling", "minReplicas"):
                args += ["--set", f"autoscaling.maxReplicas={INT32_MAX}"]  # 645: the ceiling may not sit below the floor
            if path[0] == "database":
                args += ["--set", "database.create=true"]
            result = helm(*args)
        if ok:
            assert result.returncode == 0, result.stderr
        else:
            assert result.returncode != 0, f"{'.'.join(path)}={value} rendered"
            assert ".".join(path) in result.stderr and str(INT32_MAX) in result.stderr, result.stderr


@pytest.mark.parametrize("bad", ["abc", 1.5, -1, True, [1], 1e20])
@pytest.mark.parametrize("path", [("autoscaling", "minReplicas"), ("database", "instance", "replicas")],
                         ids=["autoscaling.minReplicas", "database.instance.replicas"])
def test_a_non_whole_number_in_the_other_replica_knobs_is_refused_by_name(tmp_path, path, bad):
    """`int64` turns "abc" into 0 silently; these two knobs had no check at all."""
    result = render(write(tmp_path, replica_overlay(path, bad)), *API)
    assert result.returncode != 0, f"{'.'.join(path)}={bad!r} rendered: no refusal"
    assert ".".join(path) in result.stderr, result.stderr


def test_the_mariadb_replica_check_is_silent_when_no_instance_is_rendered(tmp_path):
    """`database.create: false` renders no MariaDB CR, so its replicas is not read."""
    overlay = write(tmp_path, {"database": {"create": False, "instance": {"replicas": "abc"}}})
    assert render(overlay, *API).returncode == 0


@pytest.mark.parametrize("source", ["file", "--set-string"])
def test_port_zero_is_refused_and_one_renders(tmp_path, source):
    path = ("database", "port")
    for value, ok in ((0, False), (1, True)):
        if source == "file":
            result = render(write(tmp_path, overlay_for(path, value)))
        else:
            result = helm(*set_args(path, "--set-string", str(value)))
        if ok:
            assert result.returncode == 0, result.stderr
            assert env_value(result.stdout, "DB_PORT") == f'"{value}"'
        else:
            assert result.returncode != 0, "port 0 rendered"
            assert "database.port" in result.stderr and "at least 1" in result.stderr, result.stderr


# --- 482 item 2: autoscaling.minReplicas >= 2 while autoscaling is on (D55) --------
# RULED 2026-11-03: D55 makes two pods a correctness property, so KEDA `minReplicaCount`
# below 2 is refused at render. `replicaCount: 0` stays legal while autoscaling is off.


def min_overlay(value) -> dict:
    return {"autoscaling": {"enabled": True, "minReplicas": value}}


@pytest.mark.parametrize("value", [0, 1, "0", "1"], ids=repr)
def test_autoscaling_on_with_min_replicas_below_two_is_refused_by_name(tmp_path, value):
    result = render(write(tmp_path, min_overlay(value)), *API)
    assert result.returncode != 0, f"minReplicas={value!r} rendered: no refusal"
    assert "autoscaling.minReplicas" in result.stderr and "at least 2" in result.stderr, result.stderr


@pytest.mark.parametrize("value", [2, 3, "2"], ids=repr)
def test_autoscaling_on_with_min_replicas_two_or_more_renders(tmp_path, value):
    result = render(write(tmp_path, min_overlay(value)), *API)
    assert result.returncode == 0, result.stderr
    assert rendered_field(result.stdout, "ScaledObject", ("spec", "minReplicaCount")) == int(value)


def test_the_min_replicas_floor_is_not_read_while_autoscaling_is_off(tmp_path):
    body = {"autoscaling": {"enabled": False, "minReplicas": 0}, "replicaCount": 0}
    result = render(write(tmp_path, body), *API)
    assert result.returncode == 0, result.stderr
    assert rendered_field(result.stdout, "Deployment", ("spec", "replicas")) == 0


# --- 645: autoscaling.maxReplicas >= autoscaling.minReplicas while autoscaling is on ----
# KEDA took `maxReplicaCount` below `minReplicaCount` without a word. Every case keeps
# `minReplicas` at 2 or more, so the D55 floor above cannot be what refuses it, and sets
# `replicaCount` to a third value, so a check that compared against it is caught.


def max_overlay(minimum, maximum, replica_count, enabled=True) -> dict:
    return {
        "autoscaling": {"enabled": enabled, "minReplicas": minimum, "maxReplicas": maximum},
        "replicaCount": replica_count,
    }


@pytest.mark.parametrize("minimum,maximum", [(2, 0), (2, 1), (5, 4), ("3", "2"), (3, "2")], ids=repr)
def test_autoscaling_on_with_max_replicas_below_min_replicas_is_refused_by_name(tmp_path, minimum, maximum):
    result = render(write(tmp_path, max_overlay(minimum, maximum, 1)), *API)
    assert result.returncode != 0, f"min={minimum!r} max={maximum!r} rendered: no refusal"
    assert "`autoscaling.maxReplicas`" in result.stderr, result.stderr
    assert "at least `autoscaling.minReplicas`" in result.stderr, result.stderr


@pytest.mark.parametrize("minimum,maximum", [(2, 2), ("3", "3"), (5, 5), (2, 3), ("2", 6)], ids=repr)
def test_autoscaling_on_with_max_replicas_at_or_above_min_replicas_renders(tmp_path, minimum, maximum):
    result = render(write(tmp_path, max_overlay(minimum, maximum, 9)), *API)
    assert result.returncode == 0, result.stderr
    assert rendered_field(result.stdout, "ScaledObject", ("spec", "minReplicaCount")) == int(minimum)
    assert rendered_field(result.stdout, "ScaledObject", ("spec", "maxReplicaCount")) == int(maximum)


def test_the_max_replicas_ceiling_is_not_read_while_autoscaling_is_off(tmp_path):
    result = render(write(tmp_path, max_overlay(5, 1, 3, enabled=False)), *API)
    assert result.returncode == 0, result.stderr
    assert rendered_field(result.stdout, "Deployment", ("spec", "replicas")) == 3


# --- 645: database.instance.replicas >= 1 while database.create is true ---------------
# `replicas: 0` rendered a MariaDB with no pods. The floor is 1, not 3: `values.yaml` and
# the MariaDB plan both keep one replica, and say more than one is Galera; no document
# sets a Galera minimum, so none is invented here.

INSTANCE_REPLICAS = ("database", "instance", "replicas")


@pytest.mark.parametrize("value", [0, "0"], ids=repr)
def test_create_true_with_instance_replicas_zero_is_refused_by_name(tmp_path, value):
    result = render(write(tmp_path, replica_overlay(INSTANCE_REPLICAS, value)), *API)
    assert result.returncode != 0, f"database.instance.replicas={value!r} rendered: no refusal"
    assert "`database.instance.replicas`" in result.stderr and "at least 1" in result.stderr, result.stderr


@pytest.mark.parametrize("value", [1, "1", 2, 3], ids=repr)
def test_create_true_with_instance_replicas_one_or_more_renders(tmp_path, value):
    result = render(write(tmp_path, replica_overlay(INSTANCE_REPLICAS, value)), *API)
    assert result.returncode == 0, result.stderr
    assert rendered_field(result.stdout, "MariaDB", ("spec", "replicas")) == int(value)


def test_the_instance_replicas_floor_is_not_read_while_create_is_false(tmp_path):
    body = {"database": {"create": False, "instance": {"replicas": 0}}}
    result = render(write(tmp_path, body), *API)
    assert result.returncode == 0, result.stderr
    assert "kind: MariaDB" not in result.stdout


# --- 550: the grace period, the preStop sleep and maxSkew ------------------------
# `templates/deployment.yaml` renders all three through `| int64` (yaadgaar 550). `int64`
# bends rather than refuses (1.5 to 1, "035" to 29, "abc" to 0), so the whole-number
# check in `templates/render-checks.yaml` runs BEFORE the cast. All three are bounded at
# 999999, and `maxSkew` is refused below 1 (the API requires it greater than zero).

TIMING = ["terminationGracePeriodSeconds", "preStopSleepSeconds"]
SKEW = "topologySpread.maxSkew"
REFUSED_TIMING = [1000000, 1.5, -1, "abc", "035", "0123", "", 1e18, 1e20, True]
REFUSED_SKEW = [0, "0", 1000000, 1.5, -1, "abc", "035", "", 1e20, None]


def pod_spec(stdout: str) -> dict:
    return rendered_field(stdout, "Deployment", ("spec", "template", "spec"))


def skew_overlay(value) -> dict:
    return {"topologySpread": {"enabled": True, "maxSkew": value}}


def refused_naming(result: subprocess.CompletedProcess[str], key: str, needle: str) -> None:
    assert result.returncode != 0, f"{key}: rendered, no refusal"
    assert f"`{key}`" in result.stderr and needle in result.stderr, result.stderr


def test_the_shipped_grace_period_sleep_and_skew_render():
    """35, 5 and 1 from `values.yaml` reach the pod spec. A render line made dead (for
    example under `{{- if false }}`) drops the field and fails here."""
    result = helm("template", NAME, str(CHART), "-f", str(CI_VALUES))
    assert result.returncode == 0, result.stderr
    spec = pod_spec(result.stdout)
    assert spec["terminationGracePeriodSeconds"] == 35
    assert spec["containers"][0]["lifecycle"]["preStop"]["sleep"]["seconds"] == 5
    assert spec["topologySpreadConstraints"][0]["maxSkew"] == 1


@pytest.mark.parametrize("value", [1, 35, 999999, "35", 35.0, 3.5e1], ids=repr)
def test_a_whole_grace_period_and_sleep_render_as_that_integer(tmp_path, value):
    result = render(write(tmp_path, {"terminationGracePeriodSeconds": value, "preStopSleepSeconds": value}))
    assert result.returncode == 0, result.stderr
    spec = pod_spec(result.stdout)
    assert spec["terminationGracePeriodSeconds"] == int(value)
    assert spec["containers"][0]["lifecycle"]["preStop"]["sleep"]["seconds"] == int(value)


@pytest.mark.parametrize("value", [None, 0], ids=repr)
def test_a_null_or_zero_grace_period_and_sleep_render_no_field(tmp_path, value):
    """`with` skips nil and 0, so neither field renders and kubelet's defaults apply."""
    result = render(write(tmp_path, {"terminationGracePeriodSeconds": value, "preStopSleepSeconds": value}))
    assert result.returncode == 0, result.stderr
    spec = pod_spec(result.stdout)
    assert "terminationGracePeriodSeconds" not in spec
    assert "lifecycle" not in spec["containers"][0]


@pytest.mark.parametrize("bad", REFUSED_TIMING, ids=repr)
@pytest.mark.parametrize("key", TIMING)
def test_a_grace_period_or_sleep_that_is_not_a_whole_number_in_range_is_refused(tmp_path, key, bad):
    result = render(write(tmp_path, {key: bad}))
    assert result.returncode != 0, f"{key}={bad!r} rendered: no refusal"
    assert f"`{key}`" in result.stderr, result.stderr


@pytest.mark.parametrize("key", TIMING)
def test_a_grace_period_or_sleep_above_999999_is_refused_and_999999_renders(tmp_path, key):
    refused_naming(render(write(tmp_path, {key: 1000000})), key, "at most 999999")
    assert render(write(tmp_path, {key: 999999})).returncode == 0


@pytest.mark.parametrize(("value", "ok"), [("35", True), ("035", False), ("1.5", False),
                                           ("-1", False), ("abc", False), ("1000000", False)])
@pytest.mark.parametrize("flag", ["--set-string", "--set"])
@pytest.mark.parametrize("key", TIMING)
def test_a_grace_period_or_sleep_given_on_the_command_line_is_checked_too(key, flag, value, ok):
    result = helm("template", NAME, str(CHART), "-f", str(CI_VALUES), flag, f"{key}={value}")
    if ok:
        assert result.returncode == 0, result.stderr
    else:
        assert result.returncode != 0, f"{flag} {key}={value} rendered: no refusal"
        assert f"`{key}`" in result.stderr, result.stderr


@pytest.mark.parametrize("value", [1, 2, 999999, "2", 2.0], ids=repr)
def test_a_whole_max_skew_from_one_to_999999_renders(tmp_path, value):
    result = render(write(tmp_path, skew_overlay(value)))
    assert result.returncode == 0, result.stderr
    assert pod_spec(result.stdout)["topologySpreadConstraints"][0]["maxSkew"] == int(value)


@pytest.mark.parametrize("bad", REFUSED_SKEW, ids=repr)
def test_a_max_skew_that_is_not_a_whole_number_from_one_to_999999_is_refused(tmp_path, bad):
    result = render(write(tmp_path, skew_overlay(bad)))
    assert result.returncode != 0, f"maxSkew={bad!r} rendered: no refusal"
    assert f"`{SKEW}`" in result.stderr, result.stderr


def test_a_max_skew_below_one_is_refused_and_above_999999_is_refused(tmp_path):
    refused_naming(render(write(tmp_path, skew_overlay(0))), SKEW, "at least 1")
    refused_naming(render(write(tmp_path, skew_overlay(1000000))), SKEW, "at most 999999")


@pytest.mark.parametrize(("value", "ok"), [("2", True), ("0", False), ("035", False),
                                           ("1.5", False), ("abc", False), ("1000000", False)])
@pytest.mark.parametrize("flag", ["--set-string", "--set"])
def test_a_max_skew_given_on_the_command_line_is_checked_too(flag, value, ok):
    result = helm("template", NAME, str(CHART), "-f", str(CI_VALUES), flag, f"{SKEW}={value}")
    if ok:
        assert result.returncode == 0, result.stderr
    else:
        assert result.returncode != 0, f"{flag} {SKEW}={value} rendered: no refusal"
        assert f"`{SKEW}`" in result.stderr, result.stderr


def test_the_max_skew_is_not_read_while_the_spread_is_off(tmp_path):
    result = render(write(tmp_path, {"topologySpread": {"enabled": False, "maxSkew": 1.5}}))
    assert result.returncode == 0, result.stderr
    assert "topologySpreadConstraints" not in pod_spec(result.stdout)


DEPLOYMENT = CHART / "templates" / "deployment.yaml"
# (any line that renders the key, the one form that line must take). The first is
# anchored to a whole line with re.M, and the second must re.fullmatch that line, so a
# cast copy in a comment line or in a trailing comment does not count.
CAST_SITES = {
    "grace": (
        r"^[ \t]*terminationGracePeriodSeconds: \{\{.*$",
        r"[ \t]*terminationGracePeriodSeconds: \{\{ \. \| int64 \}\}",
    ),
    "preStop": (
        r"^[ \t]*seconds: \{\{.*$",
        r"[ \t]*seconds: \{\{ \. \| int64 \}\}",
    ),
    "maxSkew": (
        r"^[ \t]*- maxSkew: \{\{.*$",
        r"[ \t]*- maxSkew: \{\{ \.Values\.topologySpread\.maxSkew \| int64 \}\}",
    ),
}


@pytest.mark.parametrize("site", CAST_SITES)
def test_the_grace_period_pre_stop_sleep_and_skew_render_through_int64(site):
    """Cast, like every other numeric knob (yaadgaar 550). The chart-baseline gate reads
    `| int64` since yadgarhq/actions v1.64.0. `| int` is not the same cast and does not
    count. Every value the check in render-checks.yaml admits renders the same bytes with
    or without the cast, so this pin is the test that holds the cast in place. Mirrors
    yadgarhq/project#92."""
    any_render, cast = CAST_SITES[site]
    renders = re.findall(any_render, DEPLOYMENT.read_text(), re.M)
    assert len(renders) == 1, f"{site}: expected one render line in deployment.yaml, found {renders!r}"
    assert re.fullmatch(cast, renders[0]), f"{site}: {renders[0].strip()!r} is not cast through int64"
