"""The four listener limits ADR-1006 adds live in ONE place each: `chart/values.schema.json`,
and the one rule the schema cannot state lives in `chart/templates/render-checks.yaml`.

yaadgaar #218. `yadgar-lifecycle` takes the stream, keepalive and header-list
limits as parameters and refuses to boot without them (ADR-0569). The chart supplies the
defaults under `server.limits` and renders each into `LISTEN_*`. This file holds the chart's
half: a bad value is refused at RENDER, before anything is deployed. The Rust half
(`tests/chart_server_limits.rs`) pins the schema bounds to the library's own ranges.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

CHART = Path(__file__).resolve().parents[2] / "chart"
CI_VALUES = CHART / "ci" / "values.yaml"

# Chart key, variable, shipped value (ADR-1006), library minimum, library maximum.
LIMITS = [
    pytest.param("maxConcurrentStreams", "LISTEN_MAX_CONCURRENT_STREAMS", "256", 1, 10000, id="streams"),
    pytest.param("keepaliveIntervalSeconds", "LISTEN_KEEPALIVE_INTERVAL_SECS", "30", 1, 3600, id="interval"),
    pytest.param("keepaliveTimeoutSeconds", "LISTEN_KEEPALIVE_TIMEOUT_SECS", "10", 1, 600, id="timeout"),
    pytest.param("maxHeaderListBytes", "LISTEN_MAX_HEADER_LIST_BYTES", "16384", 1024, 1048576, id="header"),
    pytest.param("maxConnectionAgeSeconds", "LISTEN_MAX_CONNECTION_AGE_SECS", "1800", 1, 86400, id="age"),
]


def render(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    assert binary, (
        "helm is not on PATH. This suite renders the chart, and so does the "
        "`helm lint and render` pre-commit hook — install helm rather than skip."
    )
    return subprocess.run(
        [binary, "template", "serverlimits", str(CHART), "-f", str(CI_VALUES), *arguments],
        capture_output=True,
        text=True,
    )


def refuses_missing(output: str, key: str) -> bool:
    """Helm 3 words a required-key refusal `<key> is required`, Helm 4 words it
    `missing property '<key>'`. Accept either, and demand the key name in it."""
    return f"{key} is required" in output or f"missing property '{key}'" in output


def rendered_value(manifest: str, variable: str) -> str:
    lines = manifest.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == f"- name: {variable}":
            return lines[i + 1].strip()
    raise AssertionError(f"{variable} is not rendered at all")


@pytest.mark.parametrize("key, variable, shipped, low, high", LIMITS)
def test_the_shipped_value_renders(key: str, variable: str, shipped: str, low: int, high: int) -> None:
    result = render()
    assert result.returncode == 0, result.stderr
    assert rendered_value(result.stdout, variable) == f'value: "{shipped}"'


@pytest.mark.parametrize("key, variable, shipped, low, high", LIMITS)
def test_an_explicit_null_is_refused_at_render_naming_the_key(
    key: str, variable: str, shipped: str, low: int, high: int
) -> None:
    result = render("--set", f"server.limits.{key}=null")
    assert result.returncode != 0, f"a nulled {key} rendered; the pod would only refuse at boot"
    assert key in result.stderr, result.stderr


@pytest.mark.parametrize("key, variable, shipped, low, high", LIMITS)
def test_one_below_the_minimum_is_refused_at_render(
    key: str, variable: str, shipped: str, low: int, high: int
) -> None:
    result = render("--set", f"server.limits.{key}={low - 1}")
    assert result.returncode != 0
    assert key in result.stderr, result.stderr


@pytest.mark.parametrize("key, variable, shipped, low, high", LIMITS)
def test_one_above_the_maximum_is_refused_at_render(
    key: str, variable: str, shipped: str, low: int, high: int
) -> None:
    result = render("--set", f"server.limits.{key}={high + 1}")
    assert result.returncode != 0
    assert key in result.stderr, result.stderr


@pytest.mark.parametrize("key, variable, shipped, low, high", LIMITS)
def test_a_quoted_numeral_is_refused_at_render_naming_the_key(
    key: str, variable: str, shipped: str, low: int, high: int
) -> None:
    result = render("--set-string", f"server.limits.{key}={shipped}")
    assert result.returncode != 0, f"a string-typed {key} rendered; `type: integer` did not catch it"
    assert key in result.stderr, result.stderr


@pytest.mark.parametrize(
    "key, variable, shipped, low, high",
    [p for p in LIMITS if p.values[0] != "keepaliveTimeoutSeconds"],
)
def test_the_bounds_themselves_render(key: str, variable: str, shipped: str, low: int, high: int) -> None:
    # The timeout is excluded: its own maximum (600) is not below the shipped interval (30).
    for bound in (low, high):
        extra = ["--set", f"server.limits.{key}={bound}"]
        if key == "keepaliveIntervalSeconds":
            # The interval's minimum would sit at or below the shipped timeout (10).
            extra += ["--set", "server.limits.keepaliveTimeoutSeconds=1"]
            if bound == 1:
                continue
        result = render(*extra)
        assert result.returncode == 0, result.stderr
        assert rendered_value(result.stdout, variable) == f'value: "{bound}"'


def test_a_keepalive_timeout_equal_to_the_interval_is_refused_naming_both_keys() -> None:
    result = render("--set", "server.limits.keepaliveTimeoutSeconds=30")
    assert result.returncode != 0
    assert "keepaliveTimeoutSeconds" in result.stderr, result.stderr
    assert "keepaliveIntervalSeconds" in result.stderr, result.stderr


def test_a_keepalive_timeout_above_the_interval_is_refused() -> None:
    result = render("--set", "server.limits.keepaliveTimeoutSeconds=31")
    assert result.returncode != 0
    assert "keepaliveTimeoutSeconds" in result.stderr, result.stderr


def test_a_keepalive_timeout_one_below_the_interval_renders() -> None:
    result = render("--set", "server.limits.keepaliveTimeoutSeconds=29")
    assert result.returncode == 0, result.stderr
    assert rendered_value(result.stdout, "LISTEN_KEEPALIVE_TIMEOUT_SECS") == 'value: "29"'


@pytest.mark.parametrize("block, named", [("server", "server"), ("server.limits", "limits")])
def test_a_nulled_block_is_refused_at_render_naming_the_key(block: str, named: str) -> None:
    result = render("--set", f"{block}=null")
    assert result.returncode != 0
    assert refuses_missing(result.stderr, named), result.stderr


def test_an_omitted_server_block_is_refused_by_the_schema_not_only_the_render_check() -> None:
    """ADR-1006, yaadgaar #327 ruling 3: the root `required: [server]` refuses a values
    set with no `server` at the schema, so `helm lint --strict` fails too. (Helm deletes
    a null-valued key, which is how a values set ends up without one.)"""
    result = render("--set", "server=null")
    assert result.returncode != 0
    assert refuses_missing(result.stderr, "server"), result.stderr
    binary = shutil.which("helm")
    assert binary
    lint = subprocess.run(
        [binary, "lint", "--strict", str(CHART), "-f", str(CI_VALUES), "--set", "server=null"],
        capture_output=True,
        text=True,
    )
    assert lint.returncode != 0, lint.stdout
    assert refuses_missing(lint.stdout + lint.stderr, "server"), lint.stdout + lint.stderr


def test_the_server_absent_arm_is_the_floor_when_the_schema_is_skipped() -> None:
    """The root `required: [server]` refuses `server: null` first, so the render check's own
    "`server` is absent" sentence is reached only with the schema skipped
    (`--skip-schema-validation`). Without the arm that case would say only that `server` is
    invalid (null), so the arm stays and must keep naming the key and the cause (yaadgaar #562)."""
    skipped = render("--set", "server=null", "--skip-schema-validation")
    assert skipped.returncode != 0, "a values set with no `server` rendered with the schema skipped"
    assert "`server` is absent from the values" in skipped.stderr, skipped.stderr
    validated = render("--set", "server=null")
    assert validated.returncode != 0
    assert "is absent from the values" not in validated.stderr, validated.stderr
    # The two sibling arms are the floor under the same flag: each must refuse and name its key.
    for shape, sentence in (
        ("server=5", "`server` must be a map"),
        ("server.limits=null", "`server.limits` is absent"),
    ):
        result = render("--set", shape, "--skip-schema-validation")
        assert result.returncode != 0, f"{shape} rendered with the schema skipped"
        assert sentence in result.stderr, f"{shape}: {result.stderr}"


def test_the_shipped_defaults_still_render_with_the_server_block_required() -> None:
    """Fail-closed guard: requiring `server` must not stop the chart rendering its own
    defaults. `chart/values.yaml` ships the block, so a values set that says nothing about
    `server` renders."""
    result = render()
    assert result.returncode == 0, result.stderr


def test_an_unknown_limit_is_refused_at_render() -> None:
    result = render("--set", "server.limits.timeoutSeconds=5")
    assert result.returncode != 0
    assert "timeoutSeconds" in result.stderr, result.stderr


def test_the_largest_header_list_renders_as_a_plain_integer(tmp_path: Path) -> None:
    """A number read from a values FILE is a float64, and `quote` of 1048576 prints
    `1.048576e+06`, which the binary refuses as not a whole number. (`--set` parses
    an int64, so only a file shows it.) The template pipes through `int64` first."""
    values = tmp_path / "values.yaml"
    values.write_text("server:\n  limits:\n    maxHeaderListBytes: 1048576\n")
    result = render("-f", str(values))
    assert result.returncode == 0, result.stderr
    assert rendered_value(result.stdout, "LISTEN_MAX_HEADER_LIST_BYTES") == 'value: "1048576"'
