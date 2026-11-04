"""THE STRING "0" FOR A `with`-GUARDED SECONDS KEY IS REFUSED BY NAME (yaadgaar 639).

`templates/deployment.yaml` guards `terminationGracePeriodSeconds` and
`preStopSleepSeconds` with `with`. `with` skips nil and the NUMBER 0, but every
non-empty string is true to a Go template, so `--set-string terminationGracePeriodSeconds=0`
rendered `terminationGracePeriodSeconds: 0`, an immediate SIGKILL with no drain, and
`--set-string preStopSleepSeconds=0` rendered `seconds: 0`. The whole-number check in
`templates/render-checks.yaml` admits "0", so for these two keys a STRING whose `int64`
is 0 is refused after it. The number 0, null and an absent key still render no field.

The refusal compares `int64 $value` with 0, not the exact string "0" (the reviewer's
hardening on yadgarhq/iam#173), so "00", "08" and the like stay refused even if the
whole-number regex is ever loosened. Ported from yadgarhq/gateway#208 (5cca171).

`topologySpread.maxSkew` is guarded by `if`, not `with`, and its own floor of 1 already
refuses "0", so it is not marked; the scope tests hold its existing message.

A values-file string is written with `QuotingDumper`, so helm gets a string and not
the number.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
CI_VALUES = CHART / "ci" / "values.yaml"
GRACE = "terminationGracePeriodSeconds"
PRESTOP = "preStopSleepSeconds"
SKEW = "topologySpread.maxSkew"
MARKED = (GRACE, PRESTOP)
ZERO_STRING = "guard treats as set"
NOT_WHOLE = "must be a whole number"


class QuotingDumper(yaml.SafeDumper):
    """Every string is written QUOTED, so a "0" reaches helm as a string and not the number 0."""


QuotingDumper.add_representer(
    str, lambda dumper, data: dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"')
)


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP (ADR-0650): a pass reported without helm is a pass nobody earned.
    assert binary, "helm is not on PATH; install it rather than skipping"
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def template(*extra: str) -> subprocess.CompletedProcess[str]:
    return helm("template", "x", str(CHART), "-f", str(CI_VALUES), *extra)


def render_file(body: dict, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    values = tmp_path / "values.yaml"
    values.write_text(yaml.dump(body, Dumper=QuotingDumper))
    return template("-f", str(values))


def nest(dotted: str, value) -> dict:
    for key in reversed(dotted.split(".")):
        value = {key: value}
    return value


def pod_spec(stdout: str) -> dict:
    (found,) = [
        d for d in yaml.safe_load_all(stdout)
        if isinstance(d, dict) and d.get("kind") == "Deployment"
    ]
    return found["spec"]["template"]["spec"]


def lifecycles(stdout: str) -> list:
    return [c.get("lifecycle") for c in pod_spec(stdout)["containers"]]


def rendered_zero(result: subprocess.CompletedProcess[str], key: str) -> bool:
    if result.returncode != 0:
        return False
    if key == GRACE:
        return pod_spec(result.stdout).get(GRACE) == 0
    return any(lc is not None and lc["preStop"]["sleep"]["seconds"] == 0 for lc in lifecycles(result.stdout))


def refused_as_zero_string(result: subprocess.CompletedProcess[str], key: str) -> None:
    assert result.returncode != 0, f"{key}: rendered, no refusal:\n{result.stdout[-400:]}"
    assert f"`{key}`" in result.stderr, result.stderr
    assert ZERO_STRING in result.stderr, result.stderr
    assert "yaadgaar 639" in result.stderr, result.stderr


# --- the bug: the string "0" through every channel ------------------------------

@pytest.mark.parametrize("key", MARKED)
@pytest.mark.parametrize("flag", ["--set-string", "--set"])
def test_the_string_zero_on_the_command_line_is_refused_by_name(key, flag):
    # `--set key=0` yields the int64 0, which `with` skips; only `--set-string` is a string.
    result = template(flag, f"{key}=0")
    if flag == "--set-string":
        refused_as_zero_string(result, key)
    else:
        assert result.returncode == 0, result.stderr
        assert not rendered_zero(result, key), result.stdout


@pytest.mark.parametrize("key", MARKED)
def test_the_string_zero_through_set_json_is_refused_by_name(key):
    refused_as_zero_string(template("--set-json", f'{key}="0"'), key)


@pytest.mark.parametrize("key", MARKED)
def test_the_string_zero_in_a_values_file_is_refused_by_name(key, tmp_path):
    refused_as_zero_string(render_file({key: "0"}, tmp_path), key)


def test_the_refusal_names_the_key_and_the_value():
    result = template("--set-string", f"{GRACE}=0")
    assert f'`{GRACE}` is the string "0"' in result.stderr, result.stderr


# --- the number 0 is not refused: it still renders no field ---------------------

@pytest.mark.parametrize("key", MARKED)
@pytest.mark.parametrize("source", ["set", "set-json", "file-int", "file-float", "file-null"])
def test_the_number_zero_and_null_still_render_no_field(key, source, tmp_path):
    if source == "set":
        result = template("--set", f"{key}=0")
    elif source == "set-json":
        result = template("--set-json", f"{key}=0")
    else:
        value = {"file-int": 0, "file-float": 0.0, "file-null": None}[source]
        result = render_file({key: value}, tmp_path)
    assert result.returncode == 0, result.stderr
    if key == GRACE:
        assert GRACE not in pod_spec(result.stdout)
    else:
        assert all(lc is None for lc in lifecycles(result.stdout))


@pytest.mark.parametrize("key", MARKED)
@pytest.mark.parametrize("value", ["1", "7", "35", "999999"])
def test_a_non_zero_digit_string_still_renders_its_value(key, value, tmp_path):
    result = render_file({key: value}, tmp_path)
    assert result.returncode == 0, result.stderr
    if key == GRACE:
        assert pod_spec(result.stdout)[GRACE] == int(value)
    else:
        assert lifecycles(result.stdout)[0]["preStop"]["sleep"]["seconds"] == int(value)


# --- every spelling of zero is refused or renders no field ----------------------

STRINGS = ["0", "00", "000", "08", "09", " 0", "0 ", "0.0", "-0", "+0", "0x0", "0e0", ""]
NUMBERS = [0, 0.0, -0.0]


@pytest.mark.parametrize("key", MARKED)
@pytest.mark.parametrize("value", STRINGS + NUMBERS, ids=repr)
def test_no_zero_spelling_in_a_values_file_renders_zero(key, value, tmp_path):
    result = render_file({key: value}, tmp_path)
    assert not rendered_zero(result, key), result.stdout


@pytest.mark.parametrize("key", MARKED)
@pytest.mark.parametrize("flag", ["--set", "--set-string"])
@pytest.mark.parametrize("value", STRINGS, ids=repr)
def test_no_zero_spelling_on_the_command_line_renders_zero(key, flag, value):
    result = template(flag, f"{key}={value}")
    assert not rendered_zero(result, key), result.stdout


@pytest.mark.parametrize("key", MARKED)
@pytest.mark.parametrize("value", ['"0"', '"00"', '"08"', "0", "0.0", "-0"], ids=repr)
def test_no_zero_spelling_through_set_json_renders_zero(key, value):
    result = template("--set-json", f"{key}={value}")
    assert not rendered_zero(result, key), result.stdout


@pytest.mark.parametrize("key", MARKED)
def test_the_detector_sees_a_rendered_field(key, tmp_path):
    # Control: "not zero" above means something only if a rendered field is seen.
    result = render_file({key: "7"}, tmp_path)
    assert result.returncode == 0, result.stderr
    assert not rendered_zero(result, key)
    if key == GRACE:
        assert pod_spec(result.stdout)[GRACE] == 7
    else:
        assert lifecycles(result.stdout)[0]["preStop"]["sleep"]["seconds"] == 7


# --- scope: the carve-out is narrow and the order is fixed -----------------------

@pytest.mark.parametrize("key", MARKED)
@pytest.mark.parametrize("value", ["00", "000", "08", "0123", "007", "01", ""], ids=repr)
def test_a_malformed_zero_string_keeps_the_whole_number_refusal(key, value, tmp_path):
    result = render_file({key: value}, tmp_path)
    assert result.returncode != 0, result.stdout
    assert f"`{key}`" in result.stderr and NOT_WHOLE in result.stderr, result.stderr
    assert ZERO_STRING not in result.stderr, result.stderr


@pytest.mark.parametrize("key", MARKED)
@pytest.mark.parametrize("value", ["abc", " 0", "0 ", "0.0", "-0", "+0", "0x0", "0e0"], ids=repr)
def test_every_other_string_that_could_mean_zero_is_refused_as_not_whole(key, value, tmp_path):
    result = render_file({key: value}, tmp_path)
    assert result.returncode != 0, result.stdout
    assert f"`{key}`" in result.stderr and NOT_WHOLE in result.stderr, result.stderr
    assert ZERO_STRING not in result.stderr, result.stderr


@pytest.mark.parametrize("flag", ["--set-string", "--set"])
def test_the_string_zero_replica_count_still_renders_zero_replicas(flag):
    result = template(flag, "replicaCount=0")
    assert result.returncode == 0, result.stderr
    assert "replicas: 0\n" in result.stdout


def test_the_string_zero_replica_count_in_a_values_file_still_renders(tmp_path):
    result = render_file({"replicaCount": "0"}, tmp_path)
    assert result.returncode == 0, result.stderr
    assert "replicas: 0\n" in result.stdout


@pytest.mark.parametrize("flag", ["--set-string", "--set"])
def test_a_zero_port_keeps_the_minimum_refusal_not_the_zero_string_one(flag):
    result = template(flag, "database.port=0")
    assert result.returncode != 0, result.stdout
    assert "`database.port`" in result.stderr and "at least 1" in result.stderr, result.stderr
    assert ZERO_STRING not in result.stderr, result.stderr


@pytest.mark.parametrize("flag", ["--set-string", "--set"])
def test_a_zero_max_skew_keeps_the_minimum_refusal_not_the_zero_string_one(flag):
    result = template(flag, f"{SKEW}=0")
    assert result.returncode != 0, result.stdout
    assert f"`{SKEW}`" in result.stderr and "at least 1" in result.stderr, result.stderr
    assert ZERO_STRING not in result.stderr, result.stderr


@pytest.mark.parametrize("key", ["database.maxConnections", "database.engineMaxConnections"])
def test_another_numeric_knob_never_gets_the_zero_string_refusal(key):
    result = template("--set-string", f"{key}=0")
    assert ZERO_STRING not in result.stderr, result.stderr
