"""THE RENDER-CHECK HARNESS: one constructed red/green pair per check the chart declares.

COPIED FROM `yadgarhq/platform`'s `scripts/tests/test_render_checks.py` AT
`origin/main`, NOT RE-DERIVED (ADR-0679). That file is the worked reference for this
construction; a matcher a sibling has hardened is copied, because the measurements
below took three rounds to get right and a second derivation gets them wrong in a
new way. What changes here is named at the bottom of this docstring and nowhere
else.

WHAT A RENDER CHECK IS FOR. A toggle GATES a resource — it says "render a MariaDB".
It does not DIAGNOSE a missing prerequisite: a toggle set true on a cluster with no
mariadb-operator renders cleanly and then fails at apply with `no matches for kind
MariaDB`, half-way through an install, naming a kind rather than an operator
somebody has to install. `templates/render-checks.yaml` turns that into a
render-time refusal that names the operator, the API group and the toggle that asked
for it.

THE TRAP, MEASURED ON helm 3.18.4 AND 4.3.0 AND NOT NEGOTIABLE, AND IT DECIDES HOW
BOTH CASES BELOW ARE CONSTRUCTED. A plain `helm template` with NO `--api-versions`
does not populate `.Capabilities.APIVersions` with CRD-backed groups at all — it
carries helm's built-in Kubernetes groups and nothing else — so
`.Capabilities.APIVersions.Has "k8s.mariadb.com/v1alpha1"` answers FALSE whatever the
cluster holds, and the check refuses for the RENDERER'S reason rather than for the
target's. A red case built that way cannot tell "the check works" apart from "the
renderer always answers false", which makes it no evidence at all.

SO BOTH CASES PASS `--api-versions`, AND THEY DIFFER ONLY IN WHAT IS IN IT.
Measured at the same time: `--api-versions` ADDS to helm's built-in set rather
than replacing it. THAT IS WHY THE FILLER MUST NOT BE BUILT IN: a built-in group
passed through `--api-versions` leaves `.Has` unchanged for every group, so the
render would be indistinguishable from a bare one and the red case would prove
nothing. Say `.Has` and not "changes nothing observable", because the LENGTH does
move — measured, a built-in group passed through `--api-versions` is APPENDED as a
duplicate, so `len .Capabilities.APIVersions` grows by one while `.Has` answers the
same for every group. A tripwire written on the length therefore reports a built-in
group as not built in, inverting the check it exists to protect.
`assert_the_red_group_is_not_built_in` below reads `.Has` and never the length.

THE CONSTRUCTION IS STATED OVER ALL THE CHECKS THE RENDER EXERCISES, NEVER OVER ONE
ALONE, because `fail` aborts the WHOLE chart render at the FIRST failing check and
the refusal names only that check. A red case that leaves a SECOND check unsatisfied
refuses for THAT check's reason rather than for the reason of the check under test —
the same defect one level up from the bare render refusing for the renderer's reason.
So, for a render exercising a set of checks:

  GREEN          `--api-versions` for EVERY group the render's checks ask for. It
                 must succeed and render objects.
  RED, check i   every one of those groups EXCEPT i's, PLUS the filler. It must
                 refuse, and the refusal must name check i's operator. That last
                 clause is what makes the refusal ATTRIBUTABLE to the check under
                 test, and it is the assertion a builder who meets a red suite while
                 adding a check is most tempted to delete. Deleting it is the
                 disarmament this harness exists to prevent.

THE FILLER STAYS IN THE RED CASE AT EVERY COUNT, THE ONE-CHECK CHART INCLUDED — and
THIS chart is the one-check case, so the clause is load-bearing here rather than
hypothetical. With one check "every group except i's" is empty, so dropping the
filler collapses the red case back into the bare render this docstring forbids. At
one check the construction reduces to the filler alone; at two or more it does not.

THE FILLER CARRIES A TRIPWIRE ASSERTING TWO THINGS, and both run BEFORE any red case.
First, that the filler is absent from a BARE render's `.Capabilities.APIVersions`
(`assert_the_red_group_is_not_built_in`). Second, that the filler is not one of the
groups the chart's own checks ask for (`assert_the_filler_is_not_a_declared_group`) —
an obligation the generalised red case creates. A colliding filler does not pass
silently: measured, the red case for the group it collides with SUCCEEDS and renders
every object. But what goes red is that check's own red case, reported as "this red
case did not refuse", which names a symptom rather than the cause. The second
assertion names the cause, which is why it runs first.

IT ASSERTS HOW MANY PAIRS IT EXERCISED, against a number written here. The rule the
number is computed from is ONE PAIR PER RENDER CHECK THE CHART DECLARES — not per
CRD-backed kind, and not per API GROUP either, because one toggle can render several
kinds, from more than one group, behind ONE check. `templates/render-checks.yaml` is
where each check states what it guards, and the count of checks is never to be read
off the count of kinds rendered. `EXPECTED_RENDER_CHECKS` below is the one place the
number lives. Printing a count is not asserting one, and the difference is the whole
point: a harness that quietly exercises one fewer check after somebody deletes one is
the "passes having examined nothing" failure wearing a green tick.

AND THE CONSTRUCTION IS PROVED AT A COUNT THIS CHART DOES NOT CONTROL.
`test_the_construction_is_correct_at_two_checks` builds a throwaway TWO-check chart
around THIS chart's own `_require_api.tpl` and runs the SAME construction over it.
The fixture's count is `FIXTURE_RENDER_CHECKS`, which is two whatever
`EXPECTED_RENDER_CHECKS` happens to say — so the generalisation stays proved at two
on a chart declaring one, and stays proved on the next chart this file is copied into
whatever that one declares. THIS PARAGRAPH IS DELIBERATELY WRITTEN OVER NO PARTICULAR
COUNT: this file is copied into every chart that carries a render check, and a reason
stated in terms of one chart's count arrives false in the next.

WHAT DIFFERS FROM THE `platform` REFERENCE, so a reader diffing the two meets the
list rather than reconstructing it:

  - the template name is `iam-db.require-api`, not `platform.require-api`. Helm
    template names are GLOBAL across a chart tree, and at the plan's step 9 the
    parent renders `platform`, `iam-db`, `project-db` and `task-db` in ONE namespace
    — three charts defining one name is a collision that is invisible in each of
    them alone. `CHART` below is the one place the name is written, and the
    `INVOCATION` regex and the two-check fixture are both built from it.
  - this chart declares ONE check, so `EXPECTED_RENDER_CHECKS` is 1.
  - there is no `example/values.yaml` here. The renders that must reach the check
    pass `--set database.create=true` instead, which is `TOGGLE_ON` below.
  - `test_the_checks_are_unreachable_at_the_chart_defaults` cannot assert the
    defaults render NOTHING, because this chart's defaults render a Deployment, a
    Service, a ServiceAccount and a PodDisruptionBudget. It asserts instead that
    they render no object of the checked group, and `test_mariadb.py` carries the
    count those four objects are asserted against.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Iterable
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CHART = REPO / "chart"

# THE CHART'S OWN NAME, and the prefix of the template this chart defines. Helm
# template names are global across a chart tree (module docstring), so this prefix
# is what keeps three sibling `-db` charts from defining one name between them.
CHART_NAME = "iam-db"

# The toggle turned on for every render that must REACH the check. There is no
# adopter values file in this repository, and one is not added: the plan's step 9
# puts the adopter block in the PARENT's `example/values.yaml`, not here.
TOGGLE_ON = ("--set", "database.create=true")

# ── WHAT THE CHART DECLARES, WRITTEN DOWN ────────────────────────────────────
# A LITERAL, for the reason every expected count in this estate is a literal: a
# number derived from the thing under test agrees with whatever that thing happens
# to be and detects nothing.
EXPECTED_RENDER_CHECKS = 1
EXPECTED_CHECKS = {
    # THE OPERATOR'S OWN GROUP. `k8s.mariadb.com/v1alpha1` is registered by
    # mariadb-operator and by nothing else — unlike the Gateway API, which is a
    # specification several implementations register, so a check on it would name a
    # specification rather than an operator. The operator string is recorded beside
    # the toggle in `chart/values.yaml` too, and
    # `test_mariadb.py::test_the_render_check_names_the_group_the_values_file_records`
    # is the gate that keeps the two one.
    "k8s.mariadb.com/v1alpha1": "mariadb-operator",
}

# The number of checks the throwaway fixture declares, and it is a LITERAL for the
# same reason — `len(declared_checks(fixture))` would agree with a fixture whose
# second invocation the regex missed, and the two-check case would then be a
# one-check case reporting a pass.
FIXTURE_RENDER_CHECKS = 2

# A group that is NOT what any check asks for, and is NOT in helm's built-in set.
# It must not be built in: `--api-versions` ADDS to the built-in set rather than
# replacing it (see the module docstring), so a built-in group passed through it
# leaves `.Has` unchanged and the red render below would be indistinguishable from
# a bare one. It must not be a group a check asks for either: a colliding filler
# satisfies the very check whose red case it is part of, and that red case then
# renders objects instead of refusing. `assert_the_red_group_is_not_built_in` and
# `assert_the_filler_is_not_a_declared_group` are the two tripwires.
A_GROUP_NO_CHECK_ASKS_FOR = "monitoring.coreos.com/v1"

# The filler's own `--api-versions` pair, funneled through one name so the tripwire
# probe and the tail of every red case can never drift apart from each other.
FILLER_API_VERSIONS = ("--api-versions", A_GROUP_NO_CHECK_ASKS_FOR)

INVOCATION = re.compile(
    r'include\s+"%s\.require-api"\s+\(dict(?P<body>.*?)\)\s*\}\}' % re.escape(CHART_NAME),
    re.DOTALL,
)
ARGUMENT = re.compile(r'"(?P<key>apiVersion|operator|toggle)"\s+"(?P<value>[^"]+)"')


def helm(*arguments: str) -> subprocess.CompletedProcess[str]:
    binary = shutil.which("helm")
    # NOT A SKIP, and ADR-0650 is why.
    assert binary, (
        "helm is not on PATH. This suite renders the chart, and so does the "
        "`helm lint and render` pre-commit hook — install helm rather than "
        "letting either report a pass it did not earn."
    )
    return subprocess.run([binary, *arguments], capture_output=True, text=True)


def declared_checks(chart: Path) -> dict[str, str]:
    """API group -> operator, for every check the chart's RENDERED templates call. PURE.

    READ OFF THE TEMPLATES THAT RENDER, and `templates/_*` is skipped deliberately:
    helm never renders a partial, so a `fail` reachable only from one would never
    fire. Reading the definition instead of the call would count a check that
    cannot happen.
    """
    found: dict[str, str] = {}
    for template in sorted((chart / "templates").glob("*.yaml")):
        for invocation in INVOCATION.finditer(template.read_text()):
            arguments = {
                match.group("key"): match.group("value")
                for match in ARGUMENT.finditer(invocation.group("body"))
            }
            assert "apiVersion" in arguments and "operator" in arguments, (
                f"{template.name} calls the render check without naming both the API "
                f"group and the operator, so its refusal cannot name the prerequisite"
            )
            found[arguments["apiVersion"]] = arguments["operator"]
    return found


def declaration_failures(chart: Path, expected: dict[str, str]) -> list[str]:
    """How the declared checks disagree with what this harness expects. PURE."""
    found = declared_checks(chart)
    failures = []
    if len(found) != len(expected):
        failures.append(
            f"expected {len(expected)} render checks declared in the chart, "
            f"found {len(found)}: expected {sorted(expected)}, found {sorted(found)}"
        )
    if found != expected:
        failures.append(f"expected the checks {expected}, found {found}")
    return failures


def api_versions(groups: Iterable[str]) -> tuple[str, ...]:
    """`--api-versions <group>` for each group, in the order given. PURE."""
    return tuple(part for group in groups for part in ("--api-versions", group))


def green_api_versions(declared: Iterable[str]) -> tuple[str, ...]:
    """EVERY group the render's checks ask for. PURE.

    Naming one group of several is NOT a green case: the checks whose groups are
    missing refuse, and `fail` aborts the whole render at the first of them.
    """
    return api_versions(sorted(declared))


def red_api_versions(declared: Iterable[str], under_test: str) -> tuple[str, ...]:
    """Every declared group EXCEPT `under_test`'s, plus the filler. PURE.

    The other groups are what keeps the refusal ATTRIBUTABLE: without them the
    render aborts at whichever other check `fail` reaches first, and names that
    check's operator rather than this one's. The filler is what keeps the render
    distinguishable from a bare one when `under_test` is the only check there is —
    which, in this chart, it is.
    """
    return api_versions(
        sorted(group for group in declared if group != under_test)
    ) + FILLER_API_VERSIONS


def render(chart: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return helm("template", CHART_NAME, str(chart), *arguments)


def objects(stdout: str) -> list[dict]:
    return [
        document
        for document in yaml.safe_load_all(stdout)
        if isinstance(document, dict) and document.get("apiVersion")
    ]


def probe_capability(group: str, destination: Path, *api_version_arguments: str) -> bool:
    """Whether a throwaway chart's OWN render sees `group` in `.Capabilities.APIVersions`.

    A SEPARATE, ONE-TEMPLATE CHART rather than a re-read of this chart's render,
    because the thing under test here is helm's capability mechanism itself — what
    `--api-versions` does and does not add — not anything this chart declares.
    `destination` must be a fresh directory per call: two probes sharing one chart
    directory would collide on `templates/probe.yaml`.
    """
    chart = destination / "capability-probe-m-agahi"
    (chart / "templates").mkdir(parents=True)
    (chart / "Chart.yaml").write_text(
        "apiVersion: v2\nname: capability-probe-m-agahi\nversion: 0.1.0\n"
    )
    (chart / "templates" / "probe.yaml").write_text(
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "metadata:\n"
        "  name: probe\n"
        "data:\n"
        '  has: {{ .Capabilities.APIVersions.Has "%s" | quote }}\n' % group
    )
    result = helm("template", "probe", str(chart), *api_version_arguments)
    assert result.returncode == 0, result.stderr
    (configmap,) = objects(result.stdout)
    return configmap["data"]["has"] == "true"


def assert_the_red_group_is_not_built_in(tmp_path: Path) -> None:
    """The filler's first tripwire.

    PROVES BOTH HALVES OF WHAT MAKES `A_GROUP_NO_CHECK_ASKS_FOR` USABLE AS THE
    FILLER. First, that it is absent from a BARE render's `.Capabilities.APIVersions`
    — i.e. it is not one of helm's built-in groups, because a built-in group passed
    through `--api-versions` leaves `.Has` unchanged (module docstring) and the red
    render below would then be indistinguishable from a bare one. Second, that it IS
    present once passed through `FILLER_API_VERSIONS` — i.e. the tail every red case
    carries actually reaches `.Capabilities.APIVersions`, so a red case rewired to
    carry no `--api-versions` at all is caught here too.

    READ WITH `.Has`, NEVER BY COMPARING `len .Capabilities.APIVersions`. A built-in
    group passed through `--api-versions` is APPENDED as a duplicate, so the length
    moves while `.Has` does not — a length-based tripwire reports a built-in group as
    not built in and inverts the check it protects.
    """
    bare = probe_capability(A_GROUP_NO_CHECK_ASKS_FOR, tmp_path / "bare")
    assert not bare, (
        f"{A_GROUP_NO_CHECK_ASKS_FOR} is present in a bare render's "
        f".Capabilities.APIVersions, so it is one of helm's built-in groups and "
        f"the red case below can no longer be told apart from a bare render"
    )
    red = probe_capability(
        A_GROUP_NO_CHECK_ASKS_FOR, tmp_path / "red", *FILLER_API_VERSIONS
    )
    assert red, (
        f"{A_GROUP_NO_CHECK_ASKS_FOR} did not reach .Capabilities.APIVersions "
        f"through {FILLER_API_VERSIONS}, so the red render below no longer carries a "
        f"capability set that differs from a bare render"
    )


def assert_the_filler_is_not_a_declared_group(declared: dict[str, str]) -> None:
    """The filler's second tripwire, and the generalised red case is what creates it.

    The red case for check i carries every OTHER declared group plus the filler. If
    the filler IS one of the declared groups then check i's red case hands that other
    check its own group back and takes nothing away from check i, the render SUCCEEDS
    and produces objects — measured — and what goes red is the red case for the group
    collided with, reported as "this red case did not refuse". That names a symptom.
    This names the cause, which is why it runs BEFORE any red case rather than after.
    """
    assert A_GROUP_NO_CHECK_ASKS_FOR not in declared, (
        f"the filler {A_GROUP_NO_CHECK_ASKS_FOR} is one of the groups the chart's own "
        f"checks ask for ({declared[A_GROUP_NO_CHECK_ASKS_FOR]}), so it satisfies a "
        f"check whose red case it is part of and that red case renders objects "
        f"instead of refusing — choose a filler outside {sorted(declared)}"
    )


def exercise_one_pair_per_declared_check(
    chart: Path, values_arguments: tuple[str, ...], expected_pairs: int, tmp_path: Path
) -> list[dict]:
    """The construction itself, over whatever set of checks `chart` declares.

    ONE FUNCTION, CALLED FOR THIS CHART AND FOR THE TWO-CHECK FIXTURE, because a
    construction proved only at the count the chart happens to declare today is not a
    generalisation. Returns the GREEN render's objects so each caller can assert its
    own literal count.

    THE GREEN HALF IS ONE RENDER SHARED BY EVERY PAIR, and that follows from the
    construction rather than from thrift: GREEN is stated over the whole set of checks,
    so there is exactly one green argv however many checks there are.
    """
    assert_the_red_group_is_not_built_in(tmp_path)
    declared = declared_checks(chart)
    assert_the_filler_is_not_a_declared_group(declared)

    green = render(chart, *values_arguments, *green_api_versions(declared))
    assert green.returncode == 0, (
        f"the render naming every declared group {sorted(declared)} refused, so the "
        f"green half proves nothing: {green.stderr}"
    )
    rendered = objects(green.stdout)
    assert rendered, (
        f"the render naming every declared group {sorted(declared)} succeeded and "
        f"produced nothing, so the green half proves nothing"
    )

    exercised = 0
    for group, operator in sorted(declared.items()):
        red = render(chart, *values_arguments, *red_api_versions(declared, group))

        # THE RED CASE'S THIRD TRIPWIRE, ORTHOGONAL TO THE TWO ABOVE. Those guard the
        # filler CONSTANT; this one guards the CALL SITE — it reads
        # `subprocess.CompletedProcess.args`, the literal argv `helm()` ran, so a red
        # case rewritten straight to a bare `render(chart)` is caught here instead of
        # silently reverting to the bare render
        # `test_a_bare_render_refuses_too_and_that_is_the_renderers_reason` exists to
        # keep out. AT ONE CHECK — WHICH IS THIS CHART — THAT IS THE ONLY ASSERTION
        # THAT CATCHES IT: a bare render still exits non-zero and still names the one
        # operator there is, so `returncode` and the stderr assertions below all stay
        # green over a red case that proves nothing.
        #
        # EVERY CLAUSE IS PHRASED OVER SOMETHING `red_api_versions` DID NOT PRODUCE —
        # the module-level filler literal, the group under test, and the groups read
        # off the chart. Asserting `set(red_api_versions(...)) <= set(red.args)`
        # instead would compare the builder with itself and could not fail.
        assert A_GROUP_NO_CHECK_ASKS_FOR in red.args, (
            f"the red render for {operator} no longer carries the filler "
            f"{A_GROUP_NO_CHECK_ASKS_FOR}, so at one check it is a bare render: {red.args}"
        )
        assert group not in red.args, (
            f"the red render for {operator} carries {group}, the very group whose "
            f"absence it exists to refuse over: {red.args}"
        )
        for other in declared:
            if other != group:
                assert other in red.args, (
                    f"the red render for {operator} does not carry {other}, so it "
                    f"aborts at that check and names {declared[other]} rather than "
                    f"{operator}: {red.args}"
                )
        assert red.args.count("--api-versions") == len(declared), (
            f"the red render for {operator} passed --api-versions "
            f"{red.args.count('--api-versions')} times; {len(declared)} is the whole "
            f"construction — every declared group but {group}, plus the filler: {red.args}"
        )

        assert red.returncode != 0, (
            f"the render for {operator} succeeded with {group} absent from "
            f"--api-versions, so the check did not refuse"
        )
        # ATTRIBUTABILITY, AND THIS IS THE ASSERTION THE WHOLE CONSTRUCTION SERVES.
        # `fail` aborts the render at the first failing check and names only that one,
        # so a refusal naming some OTHER operator is a refusal for another check's
        # reason and says nothing about this one. Do not delete it to quiet a red
        # suite met while adding a check — fix the construction, which is what the
        # other declared groups in the argv above are for.
        assert operator in red.stderr, red.stderr
        assert group in red.stderr, red.stderr
        assert "--api-versions" in red.stderr, red.stderr

        exercised += 1

    assert exercised == expected_pairs, (
        f"expected {expected_pairs} red/green pairs, exercised {exercised}"
    )
    return rendered


def two_check_fixture(destination: Path) -> Path:
    """A throwaway chart declaring TWO render checks, built around THIS chart's partial.

    `_require_api.tpl` is COPIED rather than reimplemented, so the fixture exercises
    the refusal this chart actually ships. Both toggles default false, per the rule
    that a render check only ever sits behind a default-false toggle, and the cases
    below turn them on with `--set`.
    """
    chart = destination / "two-check-fixture-m-agahi"
    (chart / "templates").mkdir(parents=True)
    (chart / "Chart.yaml").write_text(
        "apiVersion: v2\nname: two-check-fixture-m-agahi\nversion: 0.1.0\n"
    )
    (chart / "values.yaml").write_text(
        "certificates:\n  create: false\nautoscaling:\n  enabled: false\n"
    )
    shutil.copy(
        CHART / "templates" / "_require_api.tpl", chart / "templates" / "_require_api.tpl"
    )
    (chart / "templates" / "render-checks.yaml").write_text(
        "{{- if .Values.certificates.create }}\n"
        '{{- include "%(name)s.require-api" (dict\n'
        '      "context" $\n'
        '      "apiVersion" "cert-manager.io/v1"\n'
        '      "operator" "cert-manager"\n'
        '      "toggle" "certificates.create") }}\n'
        "{{- end }}\n"
        "{{- if .Values.autoscaling.enabled }}\n"
        '{{- include "%(name)s.require-api" (dict\n'
        '      "context" $\n'
        '      "apiVersion" "keda.sh/v1alpha1"\n'
        '      "operator" "KEDA"\n'
        '      "toggle" "autoscaling.enabled") }}\n'
        "{{- end }}\n" % {"name": CHART_NAME}
    )
    (chart / "templates" / "objects.yaml").write_text(
        "{{- if .Values.certificates.create }}\n"
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: from-cert-manager\n---\n"
        "{{- end }}\n"
        "{{- if .Values.autoscaling.enabled }}\n"
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: from-keda\n"
        "{{- end }}\n"
    )
    return chart


BOTH_FIXTURE_TOGGLES_ON = (
    "--set",
    "certificates.create=true",
    "--set",
    "autoscaling.enabled=true",
)


def test_the_chart_declares_the_checks_this_harness_exercises():
    """The denominator, asserted against the chart rather than assumed."""
    assert len(EXPECTED_CHECKS) == EXPECTED_RENDER_CHECKS, (
        f"EXPECTED_CHECKS names {len(EXPECTED_CHECKS)} checks and "
        f"EXPECTED_RENDER_CHECKS says {EXPECTED_RENDER_CHECKS}"
    )
    assert declaration_failures(CHART, EXPECTED_CHECKS) == [], declaration_failures(
        CHART, EXPECTED_CHECKS
    )
    assert len(declared_checks(CHART)) == EXPECTED_RENDER_CHECKS


def test_deleting_a_check_from_the_chart_reddens_the_count(tmp_path):
    """The harness's own red case: it goes red on the COUNT, not one check quieter.

    Without this, a check deleted from the chart leaves a harness that exercises
    one fewer pair and reports a pass — a gate that cannot fail because it examined
    nothing.
    """
    copy = tmp_path / "chart"
    shutil.copytree(CHART, copy)
    (copy / "templates" / "render-checks.yaml").unlink()

    failures = declaration_failures(copy, EXPECTED_CHECKS)
    message = "\n".join(failures)
    assert failures, "a check was deleted from the chart and the harness said nothing"
    assert (
        f"expected {EXPECTED_RENDER_CHECKS} render checks declared in the chart, found 0"
        in message
    )


def test_the_red_argv_builder_keeps_the_filler_at_one_check():
    """THE ARGV TRIPWIRES' OWN META-TEST, and the counterpart of the count's.

    `test_deleting_a_check_from_the_chart_reddens_the_count` is the meta-test for the
    COUNT. The two `red.args` tripwires inside `exercise_one_pair_per_declared_check`
    had none, and at ONE check — which is this chart — they are the ONLY witness that
    the red case is not a bare render: a bare render still exits non-zero and still
    names the one operator there is. So a builder who meets a red suite while adding a
    second check and does exactly what the docstrings above warn against — deletes
    `+ FILLER_API_VERSIONS` from `red_api_versions` AND both tripwires — measures a
    fully green suite, and from then on every red case in this chart is a bare render
    proving nothing. This case is what that builder meets instead.

    IT IS NOT THE BUILDER COMPARED WITH ITSELF, which is the objection those
    tripwires' own comment raises against `set(red_api_versions(...)) <= set(red.args)`.
    The INPUT here is hand-written and the EXPECTED VALUE is the module-level literal
    — neither is produced by the function under test. What it asserts is the reduction
    the module docstring states: at one check "every declared group except the one
    under test" is empty, so the whole red argv IS the filler.
    """
    assert red_api_versions({"a"}, "a") == FILLER_API_VERSIONS


def test_the_harness_exercises_one_red_green_pair_per_declared_check(tmp_path):
    """Every declared check refuses without its group and renders with it.

    BOTH RENDERS PASS `--api-versions`, and the module docstring is where the
    measurement that forces that lives: with no `--api-versions` at all helm leaves
    every CRD-backed group out of `.Capabilities.APIVersions`, so a bare render
    refuses whatever the target holds and proves nothing about the check.
    """
    exercise_one_pair_per_declared_check(
        CHART, TOGGLE_ON, EXPECTED_RENDER_CHECKS, tmp_path
    )


def test_the_construction_is_correct_at_two_checks(tmp_path):
    """THE GENERALISATION, PROVED AT A COUNT THIS CHART DOES NOT CONTROL.

    AT ONE CHECK the construction above is indistinguishable from the narrower one it
    replaced — green naming "the group under test" and red naming "the filler alone".
    Measured on helm 3.18.4 and 4.3.0 against a two-check chart, that narrower one is
    FALSE, and `test_the_narrower_construction_is_false_at_two_checks` below is where
    that measurement is asserted rather than described.

    SO THE COUNT EXERCISED HERE IS THE FIXTURE'S, NEVER THE CHART'S, AND THAT IS WHAT
    THIS CASE BUYS. `FIXTURE_RENDER_CHECKS` is two however many checks
    `EXPECTED_RENDER_CHECKS` says the chart declares, so the generalisation is proved
    at two on a chart declaring one — which is this chart — and stays proved the day a
    chart drops back to one. This file is copied into every chart that carries a
    render check, and those charts declare different counts; a case whose reason for
    existing is read off one chart's count arrives stale in the next.

    IT ALSO ASSERTS SOMETHING NO RENDER OF A REAL CHART CAN GIVE. The fixture renders
    exactly one object per check, so the green half is asserted to produce one object
    PER CHECK rather than merely to produce something — the difference between a green
    half that exercised every check it counted and one that rendered anything at all.
    """
    fixture = two_check_fixture(tmp_path / "fixture")

    rendered = exercise_one_pair_per_declared_check(
        fixture, BOTH_FIXTURE_TOGGLES_ON, FIXTURE_RENDER_CHECKS, tmp_path / "probes"
    )
    assert len(rendered) == FIXTURE_RENDER_CHECKS, (
        f"the fixture's green render produced {len(rendered)} objects, expected "
        f"{FIXTURE_RENDER_CHECKS} — one per check, and a green half that renders "
        f"fewer is not exercising every check it counts"
    )


def test_the_narrower_construction_is_false_at_two_checks(tmp_path):
    """THE MEASUREMENT THAT FORCES THE CONSTRUCTION ABOVE. Do not simplify it away.

    Records both halves of what breaks at two checks, so a later reader who wonders
    why green does not simply name "the group under test" meets the answer as an
    assertion rather than as prose. Green built the narrower way REFUSES, naming the
    other check; and the filler alone refuses naming cert-manager and never KEDA, so
    it is not KEDA's red case at all.

    Its own red case is helm rendering every check before aborting instead of
    stopping at the first `fail`: both renders below would then behave differently
    and these assertions would go red, which is the correct outcome — the
    construction above rests on the same behaviour and would need revisiting too.
    """
    fixture = two_check_fixture(tmp_path / "fixture")

    green_the_narrower_way = render(
        fixture, *BOTH_FIXTURE_TOGGLES_ON, "--api-versions", "cert-manager.io/v1"
    )
    assert green_the_narrower_way.returncode != 0, (
        "naming only the group under test rendered a two-check chart, so the narrower "
        "construction's green case is no longer the thing this case records"
    )
    assert "KEDA" in green_the_narrower_way.stderr, green_the_narrower_way.stderr

    red_the_narrower_way = render(fixture, *BOTH_FIXTURE_TOGGLES_ON, *FILLER_API_VERSIONS)
    assert red_the_narrower_way.returncode != 0
    assert "cert-manager" in red_the_narrower_way.stderr, red_the_narrower_way.stderr
    assert "KEDA" not in red_the_narrower_way.stderr, (
        "the filler alone named KEDA, so it would be a usable red case for KEDA after "
        f"all: {red_the_narrower_way.stderr}"
    )


def test_a_bare_render_refuses_too_and_that_is_the_renderers_reason():
    """THE MEASUREMENT THAT DECIDES HOW THE RED CASE IS BUILT. Do not simplify it away.

    A render with no `--api-versions` refuses as well — but for the renderer's
    reason, not the target's, because helm populates no CRD-backed group without
    one. Asserting that refusal AS the red case would pass on a chart whose check
    named a group the target does have, which is the case the check exists to let
    through.

    IT CARRIES `TOGGLE_ON`, and without it there is nothing to measure: at this
    chart's defaults the check is unreachable and the bare render SUCCEEDS, which is
    what `test_the_checks_are_unreachable_at_the_chart_defaults` asserts.

    EXACTLY ONE DECLARED OPERATOR, NOT A NAMED ONE. `fail` aborts at the first failing
    check, so which operator a bare render names depends on the order of the
    invocations in `templates/render-checks.yaml` and changes the day a check is
    inserted above another. This asserts exactly one declared operator is named — the
    only correct answer at every count — and that the refusal says what to do about
    THAT one, which is the clause an `any(...)` rewrite would drop.
    """
    declared = declared_checks(CHART)
    bare = render(CHART, *TOGGLE_ON)
    assert bare.returncode != 0

    named = sorted(group for group, operator in declared.items() if operator in bare.stderr)
    assert len(named) == 1, (
        f"a bare render named the operators of {named} out of {sorted(declared)}; "
        f"`fail` aborts at the first failing check, so exactly one is the only "
        f"correct answer: {bare.stderr}"
    )
    (group,) = named
    # And the refusal says what to do about it, because this is the render an
    # offline reader meets first.
    assert f"--api-versions {group}" in bare.stderr, bare.stderr


def test_the_checks_are_unreachable_at_the_chart_defaults():
    """A render check may only ever sit behind a default-false toggle.

    `.Capabilities.APIVersions.Has` is false for every group outside helm's
    built-in list whenever there is no cluster, so a check reachable at the
    defaults would refuse every offline render in the estate — `helm lint
    --strict`, the shared `helm lint and render` hook, and every bare `helm
    template` in every suite. This asserts the defaults render bare, with no
    `--api-versions` and no `--set` at all.

    IT CANNOT ASSERT THE DEFAULTS RENDER NOTHING, which is what the `platform`
    reference this file was copied from asserts. This chart's defaults render a
    Deployment, a Service, a ServiceAccount and a PodDisruptionBudget, and they must
    keep doing so — `test_mariadb.py::test_the_default_render_is_unchanged_and_
    creates_no_database_instance` is where that set is counted against a literal.
    What is asserted here is the half that belongs to the render check: no object of
    a checked group is rendered at the defaults, so no check was reached.
    """
    defaults = render(CHART)
    assert defaults.returncode == 0, defaults.stderr

    declared = declared_checks(CHART)
    rendered_groups = {document["apiVersion"] for document in objects(defaults.stdout)}
    assert rendered_groups.isdisjoint(declared), (
        f"the chart's DEFAULTS render objects from {sorted(rendered_groups & set(declared))}, "
        f"a group a render check asks for — so the check is reachable at the defaults "
        f"and every offline render in the estate refuses"
    )
