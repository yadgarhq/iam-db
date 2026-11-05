"""A NULL THE CHART'S OWN values.yaml SHIPS FOR THE TWO SECONDS KEYS RENDERS NO FIELD (yaadgaar 644).

`templates/render-checks.yaml` adds `terminationGracePeriodSeconds` and
`preStopSleepSeconds` to the whole-number check only under
`hasKey ... and not (kindIs "invalid" ...)`. The `kindIs "invalid"` half looks dead,
because a null from `-f` or `--set` is deleted before any template runs. It is NOT
dead on helm 3: MEASURED, helm 3 (3.18.4 and 3.20.2) KEEPS a top-level key the chart's
own `values.yaml` sets to null (`hasKey` true, value nil), and helm 4.3.0 strips it.
Without the guard a chart-default null reaches the whole-number check and helm 3
refuses it as "must be a whole number", while helm 4 renders no field.

Both tests patch a COPY of the chart, so the shipped values stay untouched:

  * `test_a_chart_default_null_renders_no_field` runs the null-shipping chart on every
    helm it can find and asserts the render succeeds with no such field. On helm 3 it
    is the test that kills "remove the `kindIs "invalid"` guard".
  * `test_the_guardless_mutant_is_refused_on_helm_3_and_renders_on_helm_4` removes the
    guard from the copy and pins the divergence in both directions, so the first test
    is proved to reach the guard rather than assumed to.

WHICH HELM. The suite uses `helm` on PATH, as every file here does. Add one more with
`HELM3_BIN=/path/to/helm3`. CI's `precommit` job installs helm v3.18.4 before pre-commit
runs this suite, so the CI precommit leg is what kills the mutant on 3.18.4. When
no helm 3 is reachable the mutant test says so with a warning instead of passing quietly.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import warnings
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"
CI_VALUES = CHART / "ci" / "values.yaml"
KEYS = ("terminationGracePeriodSeconds", "preStopSleepSeconds")
GUARD = '(not (kindIs "invalid" .Values.{key}))'
NOT_WHOLE = "must be a whole number"


def helm_binaries() -> dict[str, int]:
    """Every helm this run can use, as {path: major version}. PATH first, then HELM3_BIN."""
    found: dict[str, int] = {}
    for candidate in (shutil.which("helm"), os.environ.get("HELM3_BIN")):
        if not candidate or candidate in found:
            continue
        out = subprocess.run(
            [candidate, "version", "--template", "{{.Version}}"], capture_output=True, text=True
        ).stdout
        match = re.match(r"v(\d+)\.", out)
        assert match, f"cannot read the version of {candidate}: {out!r}"
        found[candidate] = int(match.group(1))
    # NOT A SKIP (ADR-0650): a pass reported without helm is a pass nobody earned.
    assert found, "helm is not on PATH; install it rather than skipping"
    return found


BINARIES = helm_binaries()


def null_shipping_chart(destination: Path, *, strip_guard: bool = False) -> Path:
    """A copy of the chart whose OWN values.yaml ships both keys as null."""
    chart = destination / "chart"
    shutil.copytree(CHART, chart)
    values = chart / "values.yaml"
    text = values.read_text()
    for key in KEYS:
        text, count = re.subn(rf"(?m)^{key}:.*$", f"{key}: null", text)
        assert count == 1, f"expected exactly one top-level `{key}:` in values.yaml, found {count}"
    values.write_text(text)
    if strip_guard:
        checks = chart / "templates" / "render-checks.yaml"
        body = checks.read_text()
        for key in KEYS:
            guard = GUARD.format(key=key)
            assert body.count(guard) == 1, f"expected exactly one guard for {key}"
            body = body.replace(guard, "true")
        checks.write_text(body)
    return chart


def render(binary: str, chart: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [binary, "template", "x", str(chart), "-f", str(CI_VALUES)], capture_output=True, text=True
    )


def pod_spec(stdout: str) -> dict:
    (found,) = [
        d for d in yaml.safe_load_all(stdout) if isinstance(d, dict) and d.get("kind") == "Deployment"
    ]
    return found["spec"]["template"]["spec"]


def renders_no_field(stdout: str) -> bool:
    spec = pod_spec(stdout)
    container = spec["containers"][0]
    return "terminationGracePeriodSeconds" not in spec and "preStop" not in container.get(
        "lifecycle", {}
    )


@pytest.mark.parametrize("binary", BINARIES)
def test_a_chart_default_null_renders_no_field(binary, tmp_path):
    result = render(binary, null_shipping_chart(tmp_path))
    assert result.returncode == 0, f"helm {BINARIES[binary]} refused a chart-default null: {result.stderr}"
    assert renders_no_field(result.stdout), "a chart-default null rendered a grace or preStop field"


@pytest.mark.parametrize("binary", BINARIES)
def test_the_guardless_mutant_is_refused_on_helm_3_and_renders_on_helm_4(binary, tmp_path):
    result = render(binary, null_shipping_chart(tmp_path, strip_guard=True))
    if BINARIES[binary] == 3:
        assert result.returncode != 0 and NOT_WHOLE in result.stderr, (
            "helm 3 no longer keeps a chart-default null, so the guard is dead there: "
            f"{result.stderr}"
        )
    else:
        assert result.returncode == 0, f"helm 4 strips a chart-default null: {result.stderr}"
        assert renders_no_field(result.stdout)


def test_helm_3_is_reachable_so_the_guard_mutant_is_killed():
    if 3 not in BINARIES.values():
        warnings.warn(
            "no helm 3 on PATH or in HELM3_BIN: the guard-removal mutant is NOT killed by this "
            "run; only the CI precommit leg (helm v3.18.4) kills it",
            stacklevel=1,
        )
