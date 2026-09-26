"""THE DATABASE INSTANCE THIS CHART CREATES, and what keeps it agreeing with the pod.

THIS CHART'S FIRST CONTENT ASSERTIONS. Until this file it was covered by `helm lint
--strict` alone, which reads syntax and asserts nothing about what renders.

WHAT MOVED AND WHY IT MOVED HERE. `yadgarhq/deploy`'s `infra/databases/iam-db.yaml`
is a hand-written MariaDB CR under an Argo Application, so an adopter who installs
this chart gets the pod and no engine for it to talk to. ADR-0752 put the shared
platform layer in `yadgarhq/platform` and kept this object OUT of it, in one
sentence: "an object that exactly one module consumes does NOT go here. The three
MariaDB CRs belong to `iam-db`, `project-db` and `task-db` behind `database.create`."
This instance has exactly one consumer — the Deployment rendered beside it — and no
invariant spanning its siblings, so it belongs here.

THE TOGGLE DEFAULTS FALSE, and that is not a preference. `k8s.mariadb.com/v1alpha1`
is a CRD-backed group, so a chart that rendered this object by default would fail to
install on every cluster that has not adopted mariadb-operator — the same reason
`autoscaling.enabled` defaults false for its ScaledObject. The default render is
therefore asserted to be UNCHANGED by this whole change, against a literal count.

THE FALSE-GREEN THIS FILE IS WRITTEN AGAINST. The question "does this chart create
the engine the pod dials" has exactly one admissible haystack: the RENDERED OBJECTS.
Not a comment, not a values key read twice, not a substring of the rendered YAML —
a `yaml.dump(...)` substring search answers "the text `iam-db-mariadb` appears
somewhere", which is true of the Deployment's own env var and of any comment, and
stays true after the CR's name is changed to something else entirely. So every
equality below reads ONE RENDERED OBJECT AGAINST ANOTHER: the MariaDB CR's own
fields against the values the Deployment's OWN container actually carries. Neither
side is read from `values.yaml`, so no edit to `values.yaml` can make both sides
agree while the install is broken — which is precisely the failure
`deploy/infra/databases/iam-db.yaml`'s "THE NAMES ARE A CONTRACT WITH THE CONSUMER"
comment describes, where a wrong key mounts a Secret whose file the service cannot
find and the symptom is a connection error rather than a missing file.

EVERY GATE HERE ASSERTS THE COUNT OF WHAT IT EXAMINED. A gate that compares an empty
set of fields finds no disagreement among zero of them and reports a pass; the
comparison functions are PURE and return their failures plus the number of terms
compared, and each caller asserts that number against a literal written here.

Run: python3 -m pytest scripts/tests/ -q
"""

from __future__ import annotations

import shutil
from pathlib import Path

import yaml

from test_render_checks import (
    CHART,
    CHART_NAME,
    DATABASE_TOGGLE_ON,
    EXPECTED_CHECKS,
    REPO,
    declared_checks,
    objects,
    render,
)

# ── THE NUMBERS, WRITTEN DOWN ────────────────────────────────────────────────
# Literals, every one: a number derived from the thing under test agrees with
# whatever that thing happens to be and detects nothing.

# What this chart renders at its OWN defaults, measured at `origin/main` before the
# MariaDB CR existed and asserted UNCHANGED by it.
EXPECTED_DEFAULT_OBJECTS = 4
EXPECTED_DEFAULT_KINDS = {
    "Deployment": 1,
    "PodDisruptionBudget": 1,
    "Service": 1,
    "ServiceAccount": 1,
}

# The same set plus the instance, once `database.create` is true.
EXPECTED_OBJECTS_WITH_THE_INSTANCE = EXPECTED_DEFAULT_OBJECTS + 1

MARIADB_API_VERSION = "k8s.mariadb.com/v1alpha1"
MARIADB_KIND = "MariaDB"

# How many terms each comparison below puts side by side. Asserted rather than
# trusted: a comparison that lines up zero terms finds no disagreement among them.
EXPECTED_CONTRACT_TERMS = 4
EXPECTED_POSTURE_TERMS = 6

# THE TWO ANNOTATIONS THAT KEEP A DATA-BEARING OBJECT FROM BEING DELETED, and they
# cover DIFFERENT paths — neither is a spare for the other. `Prune=false` is read off
# the live object by gitops-engine's `pruneObject` and protects an object a render
# has DROPPED; `helm.sh/resource-policy: keep` is what Argo's app-deletion cascade
# reads in `shouldBeDeleted`, a predicate `Prune=false` is ABSENT from. Both, or the
# protection has a hole. LITERALS, and the count below is asserted for the same
# reason every count here is: a gate that compared an empty set of annotations would
# find no disagreement among zero of them.
EXPECTED_ANNOTATIONS = {
    "helm.sh/resource-policy": "keep",
    "argocd.argoproj.io/sync-options": "Prune=false",
}
EXPECTED_ANNOTATION_TERMS = 2

# The group-and-version string the render check names, recorded in `values.yaml`
# beside the toggle so an operator upgrade that moved the version turns the check red
# rather than silently weakening it.
RECORDED_GROUP_PATH = ("database", "mariadbOperator", "apiVersion")

# The environment variables the container carries for its engine, and the one whose
# VALUE is a file path rather than a name. Read off the rendered Deployment.
DB_HOST = "DB_HOST"
DB_NAME = "DB_NAME"
DB_USER = "DB_USER"
DB_PASSWORD_FILE = "DB_PASSWORD_FILE"

API_VERSIONS_FOR_THE_INSTANCE = ("--api-versions", MARIADB_API_VERSION)


# ── READING THE RENDER ───────────────────────────────────────────────────────


def chart_values(chart: Path = CHART) -> dict:
    """`values.yaml` parsed. Used ONLY where the values file is itself the subject."""
    return yaml.safe_load((chart / "values.yaml").read_text())


def render_with_the_instance(chart: Path = CHART):
    """The render with `database.create` true, which is the only one that has a CR.

    IT PASSES `--api-versions`, and it has to: the render check behind the same
    toggle refuses a render that does not name the operator's group, which is the
    whole point of that check. `test_render_checks.py` is where THAT is exercised.

    IT TURNS ON THE DATABASE TOGGLE AND NOTHING ELSE, which is why it imports
    `DATABASE_TOGGLE_ON` rather than the `TOGGLES_ON` union the render-check harness
    uses. The counts below are literals over the objects a render produces, so a
    render that also created a ScaledObject would move every one of them for a reason
    that has nothing to do with the database — and it would refuse outright, because
    the KEDA check behind that other toggle asks for a group this argv does not name.
    """
    return render(chart, *DATABASE_TOGGLE_ON, *API_VERSIONS_FOR_THE_INSTANCE)


def instances(rendered: list[dict]) -> list[dict]:
    """Every MariaDB CR in a render. PURE."""
    return [
        document
        for document in rendered
        if document.get("apiVersion") == MARIADB_API_VERSION
        and document.get("kind") == MARIADB_KIND
    ]


def the_deployment(rendered: list[dict]) -> dict:
    (deployment,) = [
        document for document in rendered if document.get("kind") == "Deployment"
    ]
    return deployment


def container_environment(deployment: dict) -> dict[str, str]:
    """`name -> value` for the serving container's env. PURE."""
    (container,) = deployment["spec"]["template"]["spec"]["containers"]
    return {
        variable["name"]: variable["value"]
        for variable in container["env"]
        if "value" in variable
    }


def mounted_password_secret(deployment: dict) -> tuple[str, str]:
    """The Secret NAME and KEY the pod reads its database password out of. PURE.

    DERIVED FROM THE POD, never from `values.yaml`, and the derivation is the point.
    `DB_PASSWORD_FILE` is an absolute path into a mounted Secret: its DIRECTORY is a
    `volumeMounts` entry, that entry names a volume, and that volume names a Secret;
    its BASENAME is the key inside that Secret. So the pair returned here is what the
    process will actually open, and comparing the CR against it is comparing the
    engine's credential with the file the service opens — which is the failure
    `deploy/infra/databases/iam-db.yaml` records having met.
    """
    (container,) = deployment["spec"]["template"]["spec"]["containers"]
    path = Path(container_environment(deployment)[DB_PASSWORD_FILE])

    mounts = {
        mount["mountPath"]: mount["name"] for mount in container.get("volumeMounts", [])
    }
    assert str(path.parent) in mounts, (
        f"{DB_PASSWORD_FILE} is {path}, and nothing is mounted at {path.parent}: "
        f"the pod's mounts are {sorted(mounts)}"
    )
    wanted = mounts[str(path.parent)]

    volumes = {
        volume["name"]: volume
        for volume in deployment["spec"]["template"]["spec"].get("volumes", [])
    }
    volume = volumes[wanted]
    assert "secret" in volume, (
        f"the volume {wanted} mounted at {path.parent} is not a Secret, so the "
        f"password the engine mints cannot be the file the pod opens: {volume}"
    )
    return volume["secret"]["secretName"], path.name


# ── THE COMPARISONS, PURE AND COUNTED ────────────────────────────────────────


class Absent:
    """What a field the render did not emit compares as. PURE.

    A COMPARISON MUST NOT RAISE ON A MISSING FIELD, and that is the difference
    between a gate and a crash. `test_dropping_a_knob_from_the_template_reddens_the_
    posture` deletes a line from the template, so the field it asserts over is GONE
    rather than wrong; a `[...]` lookup would raise `KeyError` from inside the
    comparison and the caller would never reach the assertion that names the knob.
    An absent field is a DISAGREEMENT and is reported as one.
    """

    def __repr__(self) -> str:  # pragma: no cover - only ever read in a message
        return "<absent from the render>"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Absent)

    __hash__ = None  # type: ignore[assignment]


ABSENT = Absent()


def field(document: dict, *path: str):
    """`document[a][b][c]`, answering ABSENT rather than raising. PURE."""
    here: object = document
    for key in path:
        if not isinstance(here, dict) or key not in here:
            return ABSENT
        here = here[key]
    return here


def contract_disagreements(rendered: list[dict]) -> tuple[list[str], int]:
    """How the instance and the pod disagree about the engine, and how many terms. PURE.

    BOTH SIDES COME OUT OF THE SAME RENDER. The left of each pair is a field of the
    MariaDB CR; the right is what the Deployment's own container carries. No term is
    read from `values.yaml` — a gate that compared the CR against the values file and
    the pod against the same values file would agree with any values file, including
    one that names an engine nothing creates.
    """
    (instance,) = instances(rendered)
    deployment = the_deployment(rendered)
    environment = container_environment(deployment)
    secret_name, secret_key = mounted_password_secret(deployment)

    terms = [
        (
            "the instance's name",
            field(instance, "metadata", "name"),
            f"the host the pod dials ({DB_HOST})",
            environment[DB_HOST],
        ),
        (
            "the database the instance bootstraps",
            field(instance, "spec", "database"),
            f"the database the pod opens ({DB_NAME})",
            environment[DB_NAME],
        ),
        (
            "the user the instance bootstraps",
            field(instance, "spec", "username"),
            f"the user the pod connects as ({DB_USER})",
            environment[DB_USER],
        ),
        (
            "the Secret the instance writes the password into",
            (
                field(instance, "spec", "passwordSecretKeyRef", "name"),
                field(instance, "spec", "passwordSecretKeyRef", "key"),
            ),
            f"the Secret and key the pod opens ({DB_PASSWORD_FILE})",
            (secret_name, secret_key),
        ),
    ]

    failures = [
        f"{left_name} is {left!r} and {right_name} is {right!r}"
        for left_name, left, right_name, right in terms
        if left != right
    ]
    return failures, len(terms)


def posture_disagreements(rendered: list[dict], values: dict) -> tuple[list[str], int]:
    """How the rendered instance disagrees with the knobs `values.yaml` offers. PURE.

    THE OTHER HALF, AND A DIFFERENT QUESTION FROM THE ONE ABOVE. The contract terms
    must agree with the POD; these must agree with the VALUES FILE, because they are
    knobs an adopter sets and the defect they guard against is a template that drops
    one — a `tls.required` an adopter set and the render ignored is an engine
    accepting cleartext while its values file says otherwise (ADR-0569: a value
    somebody can see must be the value that applies).
    """
    instance_values = values["database"]["instance"]
    (instance,) = instances(rendered)

    terms = [
        ("image", field(instance, "spec", "image"), instance_values["image"]),
        ("replicas", field(instance, "spec", "replicas"), instance_values["replicas"]),
        (
            "storage.size",
            field(instance, "spec", "storage", "size"),
            instance_values["storage"]["size"],
        ),
        (
            # AN EMPTY CLASS MEANS AN ABSENT FIELD, and the term says so rather than
            # comparing `""` against a `storageClassName` the template never wrote.
            # The default is empty precisely so the field is omitted and the target
            # cluster's own default StorageClass binds; a term that expected `""` in
            # the render would be satisfied only by a template writing an empty
            # class name, which is a different object and binds nothing.
            # `test_an_empty_storage_class_omits_the_field_and_a_named_one_renders_it`
            # is the gate that holds BOTH directions of this against the render.
            "storage.storageClassName",
            field(instance, "spec", "storage", "storageClassName"),
            instance_values["storage"]["className"] or ABSENT,
        ),
        (
            "tls.enabled",
            field(instance, "spec", "tls", "enabled"),
            instance_values["tls"]["enabled"],
        ),
        (
            "tls.required",
            field(instance, "spec", "tls", "required"),
            instance_values["tls"]["required"],
        ),
    ]

    failures = [
        f"the instance's {what} is {rendered_value!r} and values.yaml says {wanted!r}"
        for what, rendered_value, wanted in terms
        if rendered_value != wanted
    ]
    return failures, len(terms)


def annotation_disagreements(rendered: list[dict]) -> tuple[list[str], int]:
    """How the rendered instance's annotations differ from the two required. PURE.

    READ OFF THE RENDERED OBJECT, never off the template text. A grep for
    `resource-policy` in `templates/mariadb.yaml` is true of the comment above the
    annotation and stays true after the value is changed to `delete`.

    ABSENCE IS A DISAGREEMENT rather than a KeyError, for the reason `Absent` exists:
    the red case DELETES a line from the template, so the gate must survive the field
    being gone and report it by name.
    """
    (instance,) = instances(rendered)
    terms = [
        (name, field(instance, "metadata", "annotations", name), wanted)
        for name, wanted in sorted(EXPECTED_ANNOTATIONS.items())
    ]
    failures = [
        f"the instance's {name} annotation is {found!r} and must be {wanted!r}"
        for name, found, wanted in terms
        if found != wanted
    ]
    return failures, len(terms)


# ── THE GATES ────────────────────────────────────────────────────────────────


def test_the_default_render_is_unchanged_and_creates_no_database_instance():
    """The toggle defaults FALSE, so an adopter with no mariadb-operator still installs.

    ASSERTED AS AN EQUALITY AGAINST ZERO AND AGAINST A LITERAL OBJECT COUNT, not as a
    skip. A pass that would also report a pass on one instance is not a gate, and the
    count is what catches the other direction — a template added here that renders
    something at the defaults.
    `test_turning_the_toggle_on_reddens_the_zero_and_the_count` is the red case that
    makes both numbers falsifiable.
    """
    defaults = render(CHART)
    assert defaults.returncode == 0, defaults.stderr
    rendered = objects(defaults.stdout)

    assert instances(rendered) == [], (
        "the chart rendered a MariaDB instance at its DEFAULTS, so it now requires "
        "mariadb-operator's CRD on every cluster it installs on"
    )

    kinds: dict[str, int] = {}
    for document in rendered:
        kinds[document["kind"]] = kinds.get(document["kind"], 0) + 1
    assert kinds == EXPECTED_DEFAULT_KINDS, (
        f"the default render is {kinds}, expected {EXPECTED_DEFAULT_KINDS} — the "
        f"objects this chart rendered before `database.create` existed"
    )
    assert len(rendered) == EXPECTED_DEFAULT_OBJECTS, (
        f"the default render holds {len(rendered)} objects, expected "
        f"{EXPECTED_DEFAULT_OBJECTS}"
    )


def test_turning_the_toggle_on_reddens_the_zero_and_the_count():
    """THE RED CASE for the two numbers above, constructed rather than described.

    Without it both assertions above are satisfied by a chart that renders no
    instance under ANY values — including a `database.create` the template forgot to
    read, which is the defect a default-false toggle is most likely to hide.
    """
    with_instance = render_with_the_instance()
    assert with_instance.returncode == 0, with_instance.stderr
    rendered = objects(with_instance.stdout)

    assert len(instances(rendered)) == 1, (
        f"`database.create=true` rendered {len(instances(rendered))} MariaDB "
        f"instances, expected exactly 1 — so the zero asserted at the defaults is "
        f"not a property of the toggle"
    )
    assert len(rendered) == EXPECTED_OBJECTS_WITH_THE_INSTANCE, (
        f"`database.create=true` renders {len(rendered)} objects, expected "
        f"{EXPECTED_OBJECTS_WITH_THE_INSTANCE} — the default set plus the instance "
        f"and nothing else"
    )


def test_the_instance_bootstraps_exactly_what_the_pod_beside_it_dials():
    """THE CONTRACT, asserted between two RENDERED OBJECTS and never over the text.

    The engine's name, its database, its user and the Secret its password lands in
    are all read off the MariaDB CR; the host, database, user and password FILE are
    read off the Deployment's own container. A substring search over the rendered
    YAML would answer "that name appears somewhere", which is true of the pod's own
    env var and of every comment, and stays true when the CR names another engine
    entirely.
    """
    rendered = objects(render_with_the_instance().stdout)
    failures, compared = contract_disagreements(rendered)

    assert compared == EXPECTED_CONTRACT_TERMS, (
        f"the contract comparison lined up {compared} terms, expected "
        f"{EXPECTED_CONTRACT_TERMS} — a comparison over fewer terms finds no "
        f"disagreement among the ones it dropped"
    )
    assert failures == [], "\n".join(failures)


def test_an_instance_that_names_another_engine_reddens_the_contract(tmp_path):
    """THE RED CASE for the gate above, and it mutates the TEMPLATE, not `values.yaml`.

    WHY THE VALUES FILE CANNOT BE THE RED CASE, stated because the first draft of
    this case tried it and it went green. `templates/mariadb.yaml` names the instance
    from `database.host`, which is the same key `templates/deployment.yaml` hands the
    pod as `DB_HOST` — that shared key IS the design, and it is what makes the two
    sides agree today. Editing the key therefore moves BOTH sides and the gate stays
    silent, which says nothing about the gate.

    SO THE DEFECT IS INTRODUCED WHERE IT WOULD REALLY ARRIVE: in the template, as an
    instance named something other than what the pod dials. That is the failure this
    whole file exists for — a chart whose pod dials an engine the chart does not
    create installs cleanly, reports Synced, and crash-loops on a host that resolves
    to nothing. The gate must fail NAMING BOTH SIDES, because a failure naming one
    would not say which of the two is wrong.
    """
    copy = tmp_path / "chart"
    shutil.copytree(CHART, copy)
    template = copy / "templates" / "mariadb.yaml"

    named_from_the_host = "name: {{ .Values.database.host | quote }}"
    text = template.read_text()
    assert text.count(named_from_the_host) == 1, (
        f"the instance is no longer named `{named_from_the_host}`, so this red case "
        f"mutates nothing — re-point it at whatever names the instance now"
    )
    template.write_text(
        text.replace(
            named_from_the_host,
            'name: {{ printf "%s-somewhere-else" .Values.database.host | quote }}',
            1,
        )
    )

    rendered = objects(render_with_the_instance(copy).stdout)
    failures, compared = contract_disagreements(rendered)

    assert compared == EXPECTED_CONTRACT_TERMS, compared
    assert failures, (
        "the instance was renamed away from the host the pod dials and the contract "
        "gate said nothing"
    )
    message = "\n".join(failures)
    dialled = container_environment(the_deployment(rendered))[DB_HOST]
    assert f"{dialled}-somewhere-else" in message and dialled in message, (
        f"the failure must name BOTH the engine the chart creates and the host the "
        f"pod dials ({dialled}): {message}"
    )


def test_the_instance_carries_the_knobs_the_values_file_offers():
    """Every engine-side knob `values.yaml` offers reaches the rendered instance.

    A knob an adopter sets and the template drops is ADR-0569's defect exactly: a
    value somebody can see that is not the value that applies. `tls.required` is the
    one with teeth — it sets `require_secure_transport = ON`, and an engine that
    silently dropped it would accept cleartext over TCP while its values file said
    otherwise.
    """
    rendered = objects(render_with_the_instance().stdout)
    failures, compared = posture_disagreements(rendered, chart_values())

    assert compared == EXPECTED_POSTURE_TERMS, (
        f"the posture comparison lined up {compared} terms, expected "
        f"{EXPECTED_POSTURE_TERMS}"
    )
    assert failures == [], "\n".join(failures)


def test_dropping_a_knob_from_the_template_reddens_the_posture(tmp_path):
    """THE RED CASE for the gate above, and it mutates the TEMPLATE, not the values.

    Moving the values file would move both sides for a template that merely echoes
    it, and the gate would stay green. Deleting the `required:` line from the
    template moves the rendered side alone, which is the defect being guarded: a
    knob offered in `values.yaml` that no longer reaches the object.
    """
    copy = tmp_path / "chart"
    shutil.copytree(CHART, copy)
    template = copy / "templates" / "mariadb.yaml"
    text = template.read_text()
    kept = [line for line in text.splitlines(keepends=True) if "required:" not in line]
    assert len(kept) < len(text.splitlines()), (
        "the template carries no `required:` line, so this red case removes nothing"
    )
    template.write_text("".join(kept))

    rendered = objects(render_with_the_instance(copy).stdout)
    failures, compared = posture_disagreements(rendered, chart_values(copy))

    assert compared == EXPECTED_POSTURE_TERMS, compared
    assert failures, (
        "`tls.required` was deleted from the template and the posture gate said nothing"
    )
    assert "tls.required" in "\n".join(failures), failures


def test_the_instance_carries_the_annotations_that_keep_it_from_being_deleted():
    """M3. A data-bearing object must survive a prune AND a cascading app delete.

    THE TWO COVER DIFFERENT PATHS AND NEITHER IS A SPARE FOR THE OTHER, which is why
    this gate counts them rather than asserting "at least one is present".
    `argocd.argoproj.io/sync-options: Prune=false` is read off the LIVE object by
    gitops-engine's `pruneObject` and protects an object a render has DROPPED — the
    path a revert of the merge that turned this toggle on would take.
    `helm.sh/resource-policy: keep` is what Argo's app-deletion cascade reads in
    `shouldBeDeleted`, a predicate `Prune=false` is ABSENT from — so `argocd app
    delete --cascade` walks straight past `Prune=false` and is stopped by `keep`
    alone. Without both, some path deletes a production engine and its volume.
    """
    rendered = objects(render_with_the_instance().stdout)
    failures, compared = annotation_disagreements(rendered)

    assert compared == EXPECTED_ANNOTATION_TERMS, (
        f"the annotation comparison lined up {compared} terms, expected "
        f"{EXPECTED_ANNOTATION_TERMS} — a comparison over fewer finds no "
        f"disagreement among the ones it dropped"
    )
    assert failures == [], "\n".join(failures)


def test_deleting_either_annotation_from_the_template_reddens_the_gate(tmp_path):
    """THE RED CASE for the gate above, run ONCE PER ANNOTATION and counted.

    ONE PER ANNOTATION, not one for the pair. A red case that deletes only `keep`
    leaves a gate that could be satisfied by `Prune=false` alone still reporting a
    pass for the cascade path this object needs `keep` for — and the count below is
    what makes a silently-dropped row redden rather than quietly exercise one fewer.
    """
    exercised = 0
    for name, value in sorted(EXPECTED_ANNOTATIONS.items()):
        copy = tmp_path / name.replace("/", "_") / "chart"
        copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(CHART, copy)
        template = copy / "templates" / "mariadb.yaml"
        text = template.read_text()

        # COMMENT LINES ARE NOT CANDIDATES, and skipping them is the difference
        # between a red case and a no-op. The comment above the annotations quotes
        # both pairs verbatim while explaining which Argo path each one covers, so a
        # plain substring count over the file reads 2, and a plain filter would
        # delete the prose as well and leave the reader without the reason.
        written = f"{name}: {value}"
        lines = text.splitlines(keepends=True)
        declarations = [
            index
            for index, line in enumerate(lines)
            if written in line and not line.lstrip().startswith("#")
        ]
        assert len(declarations) == 1, (
            f"`{written}` is declared on {len(declarations)} non-comment lines of the "
            f"template, expected exactly 1 — this red case deletes a line it can find, "
            f"and a count of 0 would delete nothing and pass"
        )
        (declared_at,) = declarations
        template.write_text("".join(lines[:declared_at] + lines[declared_at + 1 :]))

        rendered = objects(render_with_the_instance(copy).stdout)
        failures, compared = annotation_disagreements(rendered)
        assert compared == EXPECTED_ANNOTATION_TERMS, compared
        assert failures, f"`{name}` was deleted from the template and the gate said nothing"
        assert name in "\n".join(failures), failures
        exercised += 1

    assert exercised == EXPECTED_ANNOTATION_TERMS, (
        f"examined {exercised} annotations, expected {EXPECTED_ANNOTATION_TERMS}"
    )


def test_an_empty_storage_class_omits_the_field_and_a_named_one_renders_it():
    """The default binds the TARGET cluster's default class; a named class is honoured.

    THE DEFAULT USED TO BE `standard`, kind's bundled local-path class, which exists
    on no other cluster: the PVC sat `Pending` for ever, the pod never scheduled, and
    nothing refused. Empty renders no `storageClassName` AT ALL — not an empty
    string, which is a different object that binds nothing — so the cluster's own
    default class applies.

    BOTH DIRECTIONS, because either alone is satisfied by a broken template. A
    template that always omitted the field would pass the first half; one that always
    wrote it would pass the second.
    """
    empty = chart_values()["database"]["instance"]["storage"]["className"]
    assert empty == "", (
        f"`database.instance.storage.className` defaults to {empty!r}; this gate is "
        f"about the EMPTY default and there is none to exercise"
    )

    at_the_default = objects(render_with_the_instance().stdout)
    (instance,) = instances(at_the_default)
    assert field(instance, "spec", "storage", "storageClassName") is ABSENT, (
        f"an empty class rendered `storageClassName: "
        f"{field(instance, 'spec', 'storage', 'storageClassName')!r}` — an empty "
        f"class name is not the same thing as no class, and binds no volume"
    )

    named = render(
        CHART,
        *DATABASE_TOGGLE_ON,
        *API_VERSIONS_FOR_THE_INSTANCE,
        "--set",
        "database.instance.storage.className=a-named-class",
    )
    assert named.returncode == 0, named.stderr
    (named_instance,) = instances(objects(named.stdout))
    assert field(named_instance, "spec", "storage", "storageClassName") == "a-named-class", (
        "a class an adopter named did not reach the instance, so the `with` omits "
        "every class rather than only the empty one"
    )


def test_the_render_check_names_the_group_the_values_file_records():
    """ONE SOURCE FOR THE OPERATOR STRING, asserted across the two files that hold it.

    The plan requires the group-and-version string to be READ OFF the operator and
    RECORDED IN THE VALUES FILE beside the check that uses it, so an operator upgrade
    that moved the version turns the check red rather than silently weakening it. The
    check itself must pass a LITERAL — `test_render_checks.py` reads the invocation's
    arguments off the template — so the string exists in two places and this is the
    gate that keeps them one.

    COPIED FROM `yadgarhq/platform`'s
    `test_shared_infrastructure.py::test_the_render_check_names_the_group_the_values_file_records`
    (ADR-0679), with `gatewayListener.envoyGateway.apiVersion` replaced by this
    chart's own recorded path.
    """
    recorded = chart_values()
    for key in RECORDED_GROUP_PATH:
        recorded = recorded[key]

    declared = declared_checks(CHART)
    assert recorded in declared, (
        f"values.yaml records {recorded} as mariadb-operator's group and the chart's "
        f"checks ask for {sorted(declared)}; the two disagree, so the recorded string "
        f"is documentation rather than the thing under test"
    )
    assert declared[recorded] == EXPECTED_CHECKS[recorded], declared[recorded]


def test_the_instance_is_the_group_the_check_guards():
    """The object rendered and the group checked are the same group.

    A check naming a group no rendered object belongs to refuses installs for a
    prerequisite this chart does not actually need, and — the direction that matters
    — an object whose group NO check names is the apply-time `no matches for kind`
    the check exists to turn into a render-time refusal.
    """
    rendered = objects(render_with_the_instance().stdout)
    (instance,) = instances(rendered)
    declared = declared_checks(CHART)

    assert instance["apiVersion"] in declared, (
        f"the instance is {instance['apiVersion']} and the chart's checks ask for "
        f"{sorted(declared)} — an object whose group no check guards fails at APPLY "
        f"naming a kind instead of at render naming an operator"
    )


def test_the_suite_reads_the_chart_this_repository_ships():
    """The paths, asserted rather than assumed — a suite reading elsewhere proves nothing."""
    assert CHART == REPO / "chart", CHART
    assert (CHART / "Chart.yaml").exists(), CHART
    assert yaml.safe_load((CHART / "Chart.yaml").read_text())["name"] == CHART_NAME
