"""The four pool knobs card C-DB2 adds live in ONE place each:
`chart/values.schema.json`.

ADR-0837, ADR-0849, card C-DB2. `yadgar-store` v0.4.0 deleted the last four
compiled-in `PoolConfig` defaults (sqlx's own 30s/600s/1800s, and the `5` this
crate's own headroom check used to hard-code as `operator_reserve`). Each
replacement is rendered from its own `database.*` chart key and read by the
binary with no fallback (`tests/boot_message.rs` holds that half). This file
holds the chart's half: the schema refuses the same mistakes at RENDER,
before anything is deployed — the same shape
`test_migration_lock_schema.py` already proved for
`database.migrationLockTimeoutSeconds`.

THE NULL CASE IS THE ONE THAT MATTERS. Helm deep-merges an adopter's values
over `chart/values.yaml`, so leaving a key out inherits its shipped value —
only an explicit `null` removes it. Without `required` in the schema that
null rendered an EMPTY env var and the pod refused only at boot; with it, the
render refuses and names the key. Measured on helm 3.18.4 (Argo's) and 4.3.0.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

CHART = Path(__file__).resolve().parents[2] / "chart"

# `tls.enabled` ships no default any more (ledger 1257, H1, ADR-0845); see
# `test_render_checks.py`'s own `CI_VALUES` for why every render in this
# suite now passes it.
CI_VALUES = CHART / "ci" / "values.yaml"

# Knob, chart key, variable, shipped value and (if any) the schema's upper
# bound. `acquireTimeoutSeconds` is the one with a `maximum`: card C-DB2
# bounds it below the CALLER's own dial REQUEST_TIMEOUT (30s) — this process
# never dials out, so the budget it has to stay under is the caller's
# (`iam`'s), not its own — so a stalled acquire can never be the deadline a
# caller's whole request runs against (see `tests/chart_request_deadline.rs`,
# the Rust half of that pin).
KNOBS = [
    pytest.param(
        "database.engineOperatorReserve",
        "DB_ENGINE_OPERATOR_RESERVE",
        "5",
        None,
        id="engineOperatorReserve",
    ),
    pytest.param(
        "database.acquireTimeoutSeconds",
        "DB_ACQUIRE_TIMEOUT_SECONDS",
        "25",
        29,
        id="acquireTimeoutSeconds",
    ),
    pytest.param(
        "database.idleTimeoutSeconds",
        "DB_IDLE_TIMEOUT_SECONDS",
        "600",
        None,
        id="idleTimeoutSeconds",
    ),
    pytest.param(
        "database.maxLifetimeSeconds",
        "DB_MAX_LIFETIME_SECONDS",
        "1800",
        None,
        id="maxLifetimeSeconds",
    ),
]


def render(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    assert binary, (
        "helm is not on PATH. This suite renders the chart, and so does the "
        "`helm lint and render` pre-commit hook — install helm rather than skip."
    )
    return subprocess.run(
        [binary, "template", "poolknobs", str(CHART), "-f", str(CI_VALUES), *arguments],
        capture_output=True,
        text=True,
    )


def rendered_value(manifest: str, variable: str) -> str:
    lines = manifest.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == f"- name: {variable}":
            return lines[i + 1].strip()
    raise AssertionError(f"{variable} is not rendered at all")


@pytest.mark.parametrize("knob, variable, shipped, maximum", KNOBS)
def test_the_shipped_value_renders(knob: str, variable: str, shipped: str, maximum: int | None) -> None:
    result = render()
    assert result.returncode == 0, result.stderr
    assert rendered_value(result.stdout, variable) == f'value: "{shipped}"'


@pytest.mark.parametrize("knob, variable, shipped, maximum", KNOBS)
def test_an_explicit_null_is_refused_at_render_naming_the_key(
    knob: str, variable: str, shipped: str, maximum: int | None
) -> None:
    result = render("--set", f"{knob}=null")
    assert result.returncode != 0, f"a nulled {knob} rendered; the pod would only refuse at boot"
    assert knob.split(".")[-1] in result.stderr, result.stderr


@pytest.mark.parametrize("knob, variable, shipped, maximum", KNOBS)
def test_zero_is_refused_at_render(knob: str, variable: str, shipped: str, maximum: int | None) -> None:
    result = render("--set", f"{knob}=0")
    assert result.returncode != 0
    assert knob.split(".")[-1] in result.stderr, result.stderr


@pytest.mark.parametrize("knob, variable, shipped, maximum", KNOBS)
def test_a_quoted_numeral_is_refused_at_render_naming_the_key(
    knob: str, variable: str, shipped: str, maximum: int | None
) -> None:
    """`type: integer` is load-bearing, not merely documentation.

    Helm's `--set-string` forces a STRING, even one that reads as a number,
    so this asserts the schema's `type` catches what a bare `minimum` alone
    would not: a values override that quotes the number (`"25"`, YAML or a
    `--set-string` CLI flag both produce this) is refused at render rather
    than reaching the binary as a string `parse_required<u64>` happens to
    accept — the parse would succeed either way, so only the schema's own
    `type` stands between a quoted override and that silent pass-through.
    """
    result = render("--set-string", f"{knob}={shipped}")
    assert result.returncode != 0, (
        f"a string-typed {knob}={shipped!r} rendered; `type: integer` did not catch it"
    )
    assert knob.split(".")[-1] in result.stderr, result.stderr


@pytest.mark.parametrize("knob, variable, shipped, maximum", KNOBS)
def test_a_stated_value_at_the_minimum_renders(
    knob: str, variable: str, shipped: str, maximum: int | None
) -> None:
    result = render("--set", f"{knob}=1")
    assert result.returncode == 0, result.stderr
    assert rendered_value(result.stdout, variable) == 'value: "1"'


def test_above_the_acquire_timeout_bound_is_refused_at_render() -> None:
    result = render("--set", "database.acquireTimeoutSeconds=30")
    assert result.returncode != 0
    assert "acquireTimeoutSeconds" in result.stderr, result.stderr


def test_the_acquire_timeout_bound_itself_renders() -> None:
    result = render("--set", "database.acquireTimeoutSeconds=29")
    assert result.returncode == 0, result.stderr
    assert rendered_value(result.stdout, "DB_ACQUIRE_TIMEOUT_SECONDS") == 'value: "29"'


def test_a_nulled_database_block_is_still_refused_at_render() -> None:
    result = render("--set", "database=null")
    assert result.returncode != 0, "a nulled database block rendered"
