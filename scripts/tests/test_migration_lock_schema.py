"""The migration lock wait's bound lives in ONE place: chart/values.schema.json.

Ledger 814, ADR-0837. `DB_MIGRATION_LOCK_TIMEOUT_SECONDS` is rendered from
`database.migrationLockTimeoutSeconds` and read by the binary with no fallback.
The binary refuses an unusable value at boot; this file holds the chart's half:
the schema refuses the same mistakes at RENDER, before anything is deployed.

THE NULL CASE IS THE ONE THAT MATTERS. Helm deep-merges an adopter's values over
`chart/values.yaml`, so leaving the key out inherits the shipped 60 — only an
explicit `null` removes it. Without `required` in the schema that null rendered an
EMPTY env var and the pod refused at boot; with it, the render refuses and names
the key. Measured on helm 3.18.4 (Argo's) and 4.3.0.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

CHART = Path(__file__).resolve().parents[2] / "chart"
KNOB = "database.migrationLockTimeoutSeconds"
VARIABLE = "DB_MIGRATION_LOCK_TIMEOUT_SECONDS"


def render(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    assert binary, (
        "helm is not on PATH. This suite renders the chart, and so does the "
        "`helm lint and render` pre-commit hook — install helm rather than skip."
    )
    return subprocess.run(
        [binary, "template", "lock", str(CHART), *arguments],
        capture_output=True,
        text=True,
    )


def rendered_value(manifest: str) -> str:
    lines = manifest.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == f"- name: {VARIABLE}":
            return lines[i + 1].strip()
    raise AssertionError(f"{VARIABLE} is not rendered at all")


def test_the_shipped_value_renders() -> None:
    result = render()
    assert result.returncode == 0, result.stderr
    assert rendered_value(result.stdout) == 'value: "60"'


def test_a_stated_value_inside_the_bound_renders() -> None:
    result = render("--set", f"{KNOB}=590")
    assert result.returncode == 0, result.stderr
    assert rendered_value(result.stdout) == 'value: "590"'


def test_an_explicit_null_is_refused_at_render_naming_the_key() -> None:
    result = render("--set", f"{KNOB}=null")
    assert result.returncode != 0, (
        "a nulled wait rendered; the pod would only refuse at boot:\n"
        + rendered_value(result.stdout)
    )
    assert "migrationLockTimeoutSeconds" in result.stderr, result.stderr


def test_a_nulled_database_block_is_refused_at_render() -> None:
    result = render("--set", "database=null")
    assert result.returncode != 0, "a nulled database block rendered"


def test_zero_is_refused_at_render() -> None:
    result = render("--set", f"{KNOB}=0")
    assert result.returncode != 0
    assert "migrationLockTimeoutSeconds" in result.stderr, result.stderr


def test_above_the_bound_is_refused_at_render() -> None:
    result = render("--set", f"{KNOB}=591")
    assert result.returncode != 0
    assert "migrationLockTimeoutSeconds" in result.stderr, result.stderr
