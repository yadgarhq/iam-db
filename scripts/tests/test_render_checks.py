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

THE FILLER STAYS IN THE RED CASE AT EVERY COUNT, THE ONE-CHECK CHART INCLUDED. With
one check "every group except i's" is empty, so dropping the filler collapses the red
case back into the bare render this docstring forbids. At one check the construction
reduces to the filler alone; at two or more it does not. This chart declares two, so
the clause is not load-bearing HERE today — it is kept stated because this file is
copied into charts that declare one, and because this chart may drop back to one.

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
    parent renders `platform` and the three `-db` charts in ONE namespace — one name
    shared between every chart that copies this partial is a collision that is
    invisible in each of them alone. `CHART` below is the one place the name is
    written, and the `INVOCATION` regex and the two-check fixture are both built
    from it.
  - this chart declares TWO checks, so `EXPECTED_RENDER_CHECKS` is 2.
  - there is no `example/values.yaml` here. The renders that must reach the checks
    pass `--set` for every toggle a check sits behind instead, which is `TOGGLES_ON`
    below.
  - `RECORDED_GROUP_PATHS` and
    `test_every_declared_check_names_the_group_the_values_file_records` are stated
    HERE, over every declared check. The `platform` reference asserts the same
    property one check at a time, in the suite that owns each object. Generalising it
    means a check added with no recorded path reddens on the map's coverage rather
    than on nobody noticing.
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

# THE TOGGLE BEHIND THE MariaDB CHECK, ALONE. `test_mariadb.py` imports THIS and not
# the union below, and the two are separate for a reason that is an assertion rather
# than a preference: that file counts the objects a render produces against literals,
# so a render of its that also created a ScaledObject would redden every count it
# owns for a reason that has nothing to do with the database.
DATABASE_TOGGLE_ON = ("--set", "database.create=true")

# THE TOGGLE BEHIND THE KEDA CHECK, ALONE.
AUTOSCALING_TOGGLE_ON = ("--set", "autoscaling.enabled=true")

# EVERY TOGGLE A DECLARED CHECK SITS BEHIND, and the renders below pass all of them,
# because the construction is stated over ALL the checks the render exercises. There
# is no adopter values file in this repository, and one is not added: the plan's step
# 9 puts the adopter block in the PARENT's `example/values.yaml`, not here.
#
# A CHECK ADDED BEHIND A TOGGLE NOBODY ADDS HERE IS CAUGHT, and it is worth saying
# where: `declared_checks` reads the template whatever the toggles say, so the green
# render names that group and the check is simply never reached — and then ITS red
# case, which removes that same group, renders successfully too and
# `red.returncode != 0` goes red with "the render for <operator> succeeded". The
# harness does not pass having examined one fewer.
TOGGLES_ON = DATABASE_TOGGLE_ON + AUTOSCALING_TOGGLE_ON

# ── WHAT THE CHART DECLARES, WRITTEN DOWN ────────────────────────────────────
# A LITERAL, for the reason every expected count in this estate is a literal: a
# number derived from the thing under test agrees with whatever that thing happens
# to be and detects nothing.
EXPECTED_RENDER_CHECKS = 2
EXPECTED_CHECKS = {
    # THE OPERATOR'S OWN GROUP. `k8s.mariadb.com/v1alpha1` is registered by
    # mariadb-operator and by nothing else — unlike the Gateway API, which is a
    # specification several implementations register, so a check on it would name a
    # specification rather than an operator. The operator string is recorded beside
    # the toggle in `chart/values.yaml` too, and
    # `test_mariadb.py::test_the_render_check_names_the_group_the_values_file_records`
    # is the gate that keeps the two one.
    "k8s.mariadb.com/v1alpha1": "mariadb-operator",
    # KEDA'S OWN GROUP, and it needs no argument the way Envoy Gateway's did in
    # `yadgarhq/platform`: `keda.sh/v1alpha1` is registered by KEDA and by nothing
    # else, so there is no sibling specification a check could name by mistake. The
    # operator string is `KEDA` in the shape the refusal prints it — an adopter reads
    # it and goes and installs the thing with that name.
    "keda.sh/v1alpha1": "KEDA",
}

# WHERE `values.yaml` RECORDS EACH CHECK'S GROUP-AND-VERSION STRING, one path per
# declared check. The rule behind the map: the string is READ OFF the operator and
# RECORDED IN THE VALUES FILE beside the toggle that asks for it, so an operator
# upgrade that moved the version turns the check red rather than silently weakening
# it. The check itself must pass a LITERAL, because `declared_checks` reads the
# invocation's arguments off the template — so the string lives in two files and
# `test_every_declared_check_names_the_group_the_values_file_records` is the gate
# that keeps them one.
RECORDED_GROUP_PATHS = {
    "k8s.mariadb.com/v1alpha1": ("database", "mariadbOperator", "apiVersion"),
    "keda.sh/v1alpha1": ("autoscaling", "kedaOperator", "apiVersion"),
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

# ── THE SHAPE OF `database.create`, AND THE ELEVEN WRITABLE SHAPES ───────────
# `templates/render-checks.yaml` and `templates/mariadb.yaml` both gate on a BARE
# TRUTHINESS TEST, which is FAIL-OPEN on a string: measured identically on helm
# 3.20.2 and 4.3.0, `database.create: "false"` — which reads as OFF to any human —
# renders a MariaDB. ADR-0797 is the rule the refusal implements: `kindIs "bool"` on
# the RAW value, with `hasKey` first because `kindOf` answers `invalid` both for a
# deleted key and for an absent one and cannot tell them apart.

# THE GROUP EVERY SHAPE RENDER NAMES, AND IT IS NOT OPTIONAL. Without it the truthy
# shapes abort at the mariadb-operator CHECK instead of at the shape refusal, and a
# red case built on the exit code alone would redden for the renderer's reason while
# reading as correct. Both refusals exit 1 (ADR-0794), so every assertion below
# discriminates on the MESSAGE.
MARIADB_API_VERSIONS = ("--api-versions", "k8s.mariadb.com/v1alpha1")

# THE THREE ARMS OF THE REFUSAL, each with the phrase its message is recognised by
# and the line that opens its block in the template. Two things follow from having
# both: every arm gets its OWN red case below (a construction that strips one arm
# and proves the shapes it owns stop being refused), and no arm can be satisfied by
# another arm's message.
SHAPE_ARMS = {
    "database-absent": (
        "`database` is absent from the values",
        '{{- if not (hasKey .Values "database") }}',
    ),
    "create-absent": (
        "`database.create` is absent.",
        '{{- if not (hasKey .Values.database "create") }}',
    ),
    "not-a-bool": (
        "`database.create` must be true or false",
        '{{- if not (kindIs "bool" .Values.database.create) }}',
    ),
}

# TEXT A REFUSAL MAY NOT CONTAIN (ADR-0794). Writing the raise text a refusal
# REPLACES into the refusal string made an assertion of the form
# `raise_text not in message` false-green forever, because the marker is then in
# both. Asserted explicitly, so a later edit cannot reintroduce it quietly.
RAISE_MARKERS = ("error calling", "nil pointer", "can't evaluate field")

# EVERY SHAPE A VALUES FILE CAN WRITE AT `database.create`, with the outcome each
# one MUST have. The bodies are WHOLE FILES and are written in one go: an earlier
# measurement in this estate appended a key to an overlay, silently nested it under
# a sibling, and produced a table where every shape read as permitted — including
# the ones that refuse. `test_the_shape_harness_measures_what_it_claims_to` is the
# tripwire that a mis-built overlay cannot pass.
#
# `("render", n)` means exit 0 with n MariaDB objects. `("refuse", arm, kind)` means
# exit 1 with THAT arm's phrase, and — where the arm is the kind test — the helm
# KIND NAME the message must print. The kind name is per row rather than shared:
# asserting only the common phrase would pass an implementation that called every
# shape a bool.
SHAPES = (
    ("bool-false", "database:\n  create: false\n", ("render", 0)),
    ("bool-true", "database:\n  create: true\n", ("render", 1)),
    ("string-false", 'database:\n  create: "false"\n', ("refuse", "not-a-bool", "string")),
    ("string-no", 'database:\n  create: "no"\n', ("refuse", "not-a-bool", "string")),
    ("string-true", 'database:\n  create: "true"\n', ("refuse", "not-a-bool", "string")),
    ("number-one", "database:\n  create: 1\n", ("refuse", "not-a-bool", "float64")),
    ("number-zero", "database:\n  create: 0\n", ("refuse", "not-a-bool", "float64")),
    # THE DELETED KEY, and it is the dangerous one ADR-0797 names. Helm DELETES a
    # null-valued key that a chart in the tree declares and restores no default, so
    # this reaches the template as `create` ABSENT — measured, on both helm lines —
    # while a values file that simply OMITS `create` gets this chart's own `false`
    # back with `hasKey` true. `kindOf` answers `invalid` for both and cannot tell
    # them apart, which is why the arm is `hasKey` rather than a kind test.
    ("create-null", "database:\n  create:\n", ("refuse", "create-absent", None)),
    ("empty-map", "database:\n  create: {}\n", ("refuse", "not-a-bool", "map")),
    ("empty-list", "database:\n  create: []\n", ("refuse", "not-a-bool", "slice")),
    # THE SAME DELETION ONE LEVEL UP, and it is what makes the first arm reachable.
    # Without this row that arm has no shape of its own and could be deleted with
    # the suite still green.
    ("database-null", "database:\n", ("refuse", "database-absent", None)),
)

# THE COUNTS, LITERALS. A gate that reports how many shapes it examined turns a
# deleted row into a red suite rather than into a quieter pass. The plan this
# implements wrote ten shapes and `8 refused, 2 rendered`; the eleventh is
# `database-null`, added so the first arm is falsifiable too.
EXPECTED_SHAPES = 11
EXPECTED_SHAPES_REFUSED = 9
EXPECTED_SHAPES_RENDERED = 2
# The MariaDB counts of the two shapes that render, in order. Both, because a
# template that rendered nothing under any shape would satisfy the first alone.
EXPECTED_RENDERED_INSTANCES = (0, 1)

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
    distinguishable from a bare one when `under_test` is the only check there is,
    which is not this chart today and is the state every chart this file is copied
    into starts in.
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
        # keep out. `returncode` and the stderr assertions below do NOT catch that
        # rewrite: a bare render still exits non-zero, and at one declared check it
        # still names the one operator there is.
        #
        # IT IS NOT THE ONLY ASSERTION THAT CATCHES IT, AND THE OTHER ONE WORKS AT
        # EVERY COUNT — ONE INCLUDED. The `--api-versions` COUNT ASSERTION BELOW
        # catches the same deletion independently, in THIS CHART'S OWN red case, at
        # one declared check as well as at two or more. A red argv that lost the
        # filler carries one fewer group than `len(declared)`, and at one check that
        # is zero against one.
        #
        # MEASURED AT ONE DECLARED CHECK, on helm 3.18.4 and 4.3.0 with identical
        # output. `+ FILLER_API_VERSIONS`, both tripwires here and
        # `test_the_red_argv_builder_keeps_the_filler_at_one_check` were deleted
        # together, over a copy of this chart reduced to its mariadb check alone. The
        # chart's own red case went red on `the red render for mariadb-operator passed
        # --api-versions 0 times; 1 is the whole construction`. An earlier revision of
        # this comment asserted the opposite and was wrong. That is a strengthening,
        # not a licence to drop either: the next chart this file is copied into
        # declares one again.
        #
        # EVERY CLAUSE IS PHRASED OVER SOMETHING `red_api_versions` DID NOT PRODUCE —
        # the module-level filler literal, the group under test, and the groups read
        # off the chart. Asserting `set(red_api_versions(...)) <= set(red.args)`
        # instead would compare the builder with itself and could not fail.
        assert A_GROUP_NO_CHECK_ASKS_FOR in red.args, (
            f"the red render for {operator} no longer carries the filler "
            f"{A_GROUP_NO_CHECK_ASKS_FOR}, so it has lost the tail that makes it "
            f"differ from a bare render — which at one declared check is the whole "
            f"of it: {red.args}"
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


def test_every_declared_check_names_the_group_the_values_file_records():
    """ONE SOURCE FOR EACH OPERATOR STRING, asserted across the two files that hold it.

    The group-and-version string is READ OFF the operator and RECORDED IN `values.yaml`
    beside the toggle that asks for it, so an operator upgrade that moved the version
    turns the check red rather than silently weakening it. The invocation must pass a
    LITERAL — `declared_checks` reads the arguments off the template — so each string
    exists in two files and this is the gate that keeps them one.

    IT IS STATED OVER EVERY DECLARED CHECK, NOT ONE, and both directions of the map are
    asserted. A check added with no recorded path reddens here on the first direction;
    a recorded path left behind after its check was deleted reddens on the second. A
    gate written for one named group would have said nothing about either.

    AND IT ASSERTS HOW MANY IT EXAMINED. A loop over an empty set of declared checks
    finds no disagreement among zero of them and reports a pass, which is the failure
    every count in this file is a literal to prevent.

    `test_mariadb.py` carries the same assertion for its own group alone, written
    before this one generalised it. It is left where it is: it is the file a reader of
    the database change opens, and a second independent statement of a property costs
    nothing.
    """
    declared = declared_checks(CHART)

    assert set(RECORDED_GROUP_PATHS) == set(declared), (
        f"the chart's checks ask for {sorted(declared)} and values.yaml records paths "
        f"for {sorted(RECORDED_GROUP_PATHS)}; a check with no recorded string is one "
        f"an operator upgrade can weaken silently, and a recorded string no check "
        f"names is documentation"
    )

    values = yaml.safe_load((CHART / "values.yaml").read_text())
    examined = 0
    for group, path in sorted(RECORDED_GROUP_PATHS.items()):
        recorded = values
        for key in path:
            assert key in recorded, (
                f"values.yaml has no {'.'.join(path)}, so {group} is recorded nowhere "
                f"beside the toggle that asks for it"
            )
            recorded = recorded[key]
        assert recorded == group, (
            f"values.yaml records {recorded} at {'.'.join(path)} and the chart's check "
            f"names {group}; the two disagree, so the recorded string is documentation "
            f"rather than the thing under test"
        )
        examined += 1

    assert examined == EXPECTED_RENDER_CHECKS, (
        f"examined {examined} recorded strings, expected {EXPECTED_RENDER_CHECKS}"
    )


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
    had none. A builder who deletes `+ FILLER_API_VERSIONS` from `red_api_versions`
    AND both tripwires turns every red case the CHART has into a bare render, and
    `returncode` and the stderr assertions do not notice: a bare render still exits
    non-zero, and at one declared check it still names the one operator there is. This
    case is what that builder meets instead.

    THE TRIPWIRES ARE NOT THE ONLY WITNESS AT ANY COUNT, AND THAT IS A MEASUREMENT
    RATHER THAN A CAUTION. Two other assertions redden under the SAME deletion.
    `test_the_construction_is_correct_at_two_checks` runs the same function over a
    fixture declaring TWO checks whatever the chart declares, so its `--api-versions`
    count assertion reddens at every chart count. The count assertion inside
    `exercise_one_pair_per_declared_check` is a THIRD witness, also at every chart
    count — ONE included, where a red argv that lost the filler carries zero groups
    against a `len(declared)` of one.

    MEASURED AT ONE DECLARED CHECK, on helm 3.18.4 and 4.3.0 with identical output.
    The filler, both tripwires and this case were deleted together, over a copy of this
    chart reduced to its mariadb check alone. The chart's own red case went red on
    `the red render for mariadb-operator passed --api-versions 0 times; 1 is the whole
    construction`. TWO earlier revisions of this docstring were wrong here. The first
    claimed the tripwires were the suite's only witness. The second scoped that claim
    to the chart's own red cases at one check. The count assertion refutes both.

    IT DOES NOT GO VACUOUS WHEN THE CHART LEAVES ONE CHECK, WHICH THIS ONE HAS DONE.
    Its input is the hand-written one-element set below and its expected value is a
    module-level literal — neither is the chart's count — so deleting
    `+ FILLER_API_VERSIONS` still reddens it here. The move to two checks changed
    NOTHING about which assertions witness that deletion: the count assertion
    witnessed it at one too. The reduction this case states is the one the module
    docstring keeps stated at every count, and the chart this file is copied into next
    declares one.

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
        CHART, TOGGLES_ON, EXPECTED_RENDER_CHECKS, tmp_path
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
    `EXPECTED_RENDER_CHECKS` says the chart declares, so the generalisation stays
    proved at two the day a chart drops back to one. This file is copied into every
    chart that carries a render check, and those charts declare different counts; a
    case whose reason for existing is read off one chart's count arrives stale in the
    next.

    THIS CHART NOW DECLARES TWO ITSELF, SO SAY WHAT THIS CASE STILL BUYS AND WHAT IT
    NO LONGER DOES. It no longer buys a count the chart does not have. What it buys is
    INDEPENDENCE OF THE SUBJECT: its own chart, its own literal, its own two groups,
    and the one-object-per-check assertion below that no render of a real chart can
    give. A chart edit that took the real count to one or to three would leave this
    case exercising two regardless, which is the property the paragraph above is
    about and the reason the fixture is not deleted now that the counts agree.

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

    IT CARRIES `TOGGLES_ON`, and without it there is nothing to measure: at this
    chart's defaults every check is unreachable and the bare render SUCCEEDS, which is
    what `test_the_checks_are_unreachable_at_the_chart_defaults` asserts.

    EXACTLY ONE DECLARED OPERATOR, NOT A NAMED ONE. `fail` aborts at the first failing
    check, so which operator a bare render names depends on the order of the
    invocations in `templates/render-checks.yaml` and changes the day a check is
    inserted above another. This asserts exactly one declared operator is named — the
    only correct answer at every count — and that the refusal says what to do about
    THAT one, which is the clause an `any(...)` rewrite would drop.
    """
    declared = declared_checks(CHART)
    bare = render(CHART, *TOGGLES_ON)
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


# ── THE SHAPE OF THE TOGGLE, M1 ──────────────────────────────────────────────


def shape_overlay(body: str, destination: Path) -> Path:
    """One shape's values file, WRITTEN AS A WHOLE FILE and read back.

    NEVER BY APPENDING, and the read-back is not ceremony. An earlier measurement in
    this estate appended a key to an overlay, silently nested it under a sibling, and
    produced a table in which every shape read as permitted — including the ones that
    refuse. A harness that measures nothing looks exactly like a harness that passes.
    """
    destination.mkdir(parents=True, exist_ok=True)
    overlay = destination / "values.yaml"
    overlay.write_text(body)
    assert overlay.read_text() == body, (
        f"the overlay at {overlay} is not the whole of what this shape writes"
    )
    return overlay


def render_the_shape(chart: Path, body: str, destination: Path):
    """One shape rendered, NAMING mariadb-operator's group.

    THE `--api-versions` IS LOAD-BEARING. Four of these shapes are truthy, so without
    it they reach the mariadb-operator render check and abort THERE — the refusal for
    the renderer's reason, not for the shape's. The red cases below would then redden
    correctly while proving nothing, which is why every shape carries it and every
    assertion discriminates on the message rather than on the exit code.
    """
    overlay = shape_overlay(body, destination)
    return render(chart, "--values", str(overlay), *MARIADB_API_VERSIONS)


def examine_the_shapes(chart: Path, destination: Path) -> tuple[list[str], int, int, list[int]]:
    """Every shape in SHAPES against `chart`: the disagreements, and what was counted.

    PURE over its arguments and it RETURNS ITS COUNTS, for the reason every gate in
    this repository does: a loop that examined zero shapes finds no disagreement among
    them and reports a pass.
    """
    failures: list[str] = []
    refused = 0
    rendered_instances: list[int] = []

    for label, body, expectation in SHAPES:
        result = render_the_shape(chart, body, destination / label)
        instances = result.stdout.count("kind: MariaDB")

        if expectation[0] == "render":
            wanted = expectation[1]
            if result.returncode != 0:
                failures.append(
                    f"{label}: expected a render and helm exited {result.returncode}: "
                    f"{result.stderr.strip()}"
                )
                continue
            rendered_instances.append(instances)
            if instances != wanted:
                failures.append(
                    f"{label}: rendered {instances} MariaDB objects, expected {wanted}"
                )
            continue

        _, arm, kind = expectation
        phrase = SHAPE_ARMS[arm][0]
        if result.returncode == 0:
            failures.append(
                f"{label}: rendered {instances} MariaDB objects and was NOT refused — "
                f"the {arm} arm did not fire"
            )
            continue
        refused += 1
        if phrase not in result.stderr:
            failures.append(
                f"{label}: refused without the {arm} arm's message ({phrase!r}): "
                f"{result.stderr.strip()}"
            )
        if CHART_NAME not in result.stderr:
            failures.append(f"{label}: the refusal does not name {CHART_NAME}: {result.stderr.strip()}")
        if kind is not None and kind not in result.stderr:
            failures.append(
                f"{label}: the refusal does not name the kind it found ({kind!r}), so it "
                f"would read the same for every wrong shape: {result.stderr.strip()}"
            )
        for marker in RAISE_MARKERS:
            if marker in result.stderr:
                failures.append(
                    f"{label}: helm RAISED rather than refusing — {marker!r} is in the "
                    f"output, so the adopter got a template trace instead of a key name"
                )

    return failures, len(SHAPES), refused, rendered_instances


def strip_arm(text: str, opening: str) -> str:
    """The template with ONE arm of the refusal removed, for a red case. PURE."""
    lines = text.splitlines(keepends=True)
    starts = [index for index, line in enumerate(lines) if line.strip() == opening.strip()]
    assert len(starts) == 1, (
        f"{opening!r} opens {len(starts)} blocks in the template, expected exactly 1 — "
        f"this red case removes a block it can find, and 0 would remove nothing and pass"
    )
    (start,) = starts
    ends = [index for index in range(start + 1, len(lines)) if lines[index].strip() == "{{- end }}"]
    assert ends, f"{opening!r} opens a block nothing closes"
    return "".join(lines[: start] + lines[ends[0] + 1 :])


def test_the_shape_harness_measures_what_it_claims_to(tmp_path):
    """THE TRIPWIRE, and it runs before the table is believed.

    A shape overlay that landed under the wrong parent — the failure mode this
    estate has actually met — leaves `database.create` at the chart's own `false`,
    and then every row reads as "not refused" or "rendered nothing" and the table
    measures the chart's defaults eleven times. So: a shape that MUST render an
    instance is rendered and the instance is counted, which is impossible unless the
    overlay reached the key; and a shape that MUST be refused is refused.
    """
    reaching = render_the_shape(CHART, "database:\n  create: true\n", tmp_path / "reaching")
    assert reaching.returncode == 0, reaching.stderr
    assert reaching.stdout.count("kind: MariaDB") == 1, (
        "an overlay setting `database.create: true` rendered no MariaDB, so it did "
        "not reach the key and no row of the table below measures anything"
    )

    refusing = render_the_shape(CHART, 'database:\n  create: "false"\n', tmp_path / "refusing")
    assert refusing.returncode != 0, refusing.stdout
    assert SHAPE_ARMS["not-a-bool"][0] in refusing.stderr, refusing.stderr


def test_every_writable_shape_of_the_toggle_is_a_bool_or_refused(tmp_path):
    """M1. Eleven shapes examined: nine refused, two rendered (0 and 1 MariaDB).

    THE COUNTS ARE ASSERTED, so a row deleted from SHAPES reddens this gate rather
    than letting it quietly examine one fewer. The two that render are BOTH asserted,
    because a chart that rendered nothing under any shape would satisfy the zero.
    """
    failures, examined, refused, rendered_instances = examine_the_shapes(CHART, tmp_path)

    assert examined == EXPECTED_SHAPES, (
        f"examined {examined} shapes, expected {EXPECTED_SHAPES}"
    )
    assert failures == [], "\n".join(failures)
    assert refused == EXPECTED_SHAPES_REFUSED, (
        f"examined {examined} shapes: {refused} refused, expected "
        f"{EXPECTED_SHAPES_REFUSED}"
    )
    assert len(rendered_instances) == EXPECTED_SHAPES_RENDERED, rendered_instances
    assert tuple(rendered_instances) == EXPECTED_RENDERED_INSTANCES, (
        f"the shapes that render produced {tuple(rendered_instances)} MariaDB "
        f"objects, expected {EXPECTED_RENDERED_INSTANCES}"
    )
    print(
        f"examined {examined} shapes: {refused} refused, "
        f"{len(rendered_instances)} rendered {tuple(rendered_instances)}"
    )


def test_stripping_an_arm_of_the_refusal_reddens_the_shapes_it_owns(tmp_path):
    """THE RED CASE, CONSTRUCTED, and run ONCE PER ARM rather than once for the guard.

    A single red case that deleted the `kindIs` block would leave the two `hasKey`
    arms unfalsifiable — either could be deleted with this suite still green, which
    is the exact shape of guard ADR-0797 was written about: one that reads as
    complete and is not. So each arm is stripped in turn and the shapes it owns are
    asserted to stop being refused for its reason.

    THE THREE ARMS FAIL DIFFERENTLY WHEN STRIPPED, and that is stated rather than
    smoothed over. Stripping `kindIs` restores the FAIL-OPEN: `"false"`, `"no"`,
    `"true"` and `1` render a MariaDB again, which is asserted below by name.
    Stripping either `hasKey` arm does not open a hole — the kind test still refuses
    a deleted key — it DEGRADES THE MESSAGE, from one that explains that helm deleted
    the adopter's key into one that reports `invalid`, or into a raw template raise.
    An arm that owns a message is still an arm; what it owns is asserted for what it
    is.
    """
    exercised = 0
    for arm, (phrase, opening) in sorted(SHAPE_ARMS.items()):
        copy = tmp_path / arm / "chart"
        copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(CHART, copy)
        template = copy / "templates" / "render-checks.yaml"
        template.write_text(strip_arm(template.read_text(), opening))

        failures, examined, _, _ = examine_the_shapes(copy, tmp_path / arm / "renders")
        assert examined == EXPECTED_SHAPES, examined
        assert failures, (
            f"the {arm} arm was stripped from the template and the table said nothing"
        )

        owned = [label for label, _body, expectation in SHAPES
                 if expectation[0] == "refuse" and expectation[1] == arm]
        assert owned, f"no shape in SHAPES exercises the {arm} arm, so it is unfalsifiable"
        for label in owned:
            assert any(failure.startswith(f"{label}:") for failure in failures), (
                f"the {arm} arm was stripped and {label} still passed: {failures}"
            )
        exercised += 1

    assert exercised == len(SHAPE_ARMS), (
        f"examined {exercised} arms of the refusal, expected {len(SHAPE_ARMS)}"
    )


def test_stripping_the_kind_test_puts_the_four_wrong_on_shapes_back(tmp_path):
    """THE DEFECT ITSELF, reconstructed: four shapes that read as OFF and create an engine.

    The arm-by-arm case above asserts that each arm's shapes stop being refused. This
    one asserts WHAT THAT COSTS for the arm that guards the fail-open, in the only
    terms that matter: with `kindIs` gone, `database.create: "false"` renders a
    MariaDB. A red case that asserted only "the suite went red" would be satisfied by
    a template that broke in any way at all.
    """
    copy = tmp_path / "chart"
    shutil.copytree(CHART, copy)
    template = copy / "templates" / "render-checks.yaml"
    template.write_text(strip_arm(template.read_text(), SHAPE_ARMS["not-a-bool"][1]))

    wrong_on = ("string-false", "string-no", "string-true", "number-one")
    bodies = {label: body for label, body, _ in SHAPES}
    for label in wrong_on:
        result = render_the_shape(copy, bodies[label], tmp_path / "renders" / label)
        assert result.returncode == 0, result.stderr
        assert result.stdout.count("kind: MariaDB") == 1, (
            f"{label} did not render a MariaDB with the kind test stripped, so this "
            f"construction does not reproduce the fail-open it is named for"
        )

    failures, examined, _, _ = examine_the_shapes(copy, tmp_path / "table")
    assert examined == EXPECTED_SHAPES, examined
    assert failures and failures[0].startswith("string-false:"), (
        f"the table must redden naming `\"false\"` first — the shape an adopter is "
        f"most likely to have written: {failures}"
    )


def test_the_shape_refusal_does_not_quote_a_raise():
    """ADR-0794: a refusal may not carry the raise text it replaces.

    Writing `error calling eq: incompatible types` into a refusal string made an
    assertion of the form `raise_text not in message` false-green forever, because
    the marker was then in both. Asserted over the TEMPLATE SOURCE, so the ban holds
    for every shape including ones nobody has written a row for yet.
    """
    text = (CHART / "templates" / "render-checks.yaml").read_text()
    for arm, (phrase, _opening) in sorted(SHAPE_ARMS.items()):
        assert phrase in text, f"the {arm} arm's message is not in the template: {phrase!r}"
    for marker in RAISE_MARKERS:
        assert marker not in text, (
            f"`templates/render-checks.yaml` contains {marker!r}, which is how a "
            f"refusal is told apart from a raise — a refusal carrying it makes that "
            f"discrimination false-green"
        )
