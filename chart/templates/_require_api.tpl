{{/*
THE RENDER CHECK: an apply-time `no matches for kind` turned into a render-time
refusal that names the prerequisite.

COPIED FROM `yadgarhq/platform`'s `chart/templates/_require_api.tpl` (ADR-0679: a
matcher a sibling has hardened is copied, never re-derived). Two things differ and
both are deliberate — the template's NAME and the prefix of the message it fails
with. Helm template names are GLOBAL across a chart tree: at the plan's step 9 the
parent renders `platform` and the three `-db` charts together in ONE namespace, so
one name shared between every chart that copies this partial would leave ONE
definition's body rendering for every caller, silently, with nothing in any one
repository's own suite able to see it.

SO THE NAMES MUST STAY PAIRWISE DISTINCT ACROSS THE ASSEMBLED TREE, and nothing in
THIS repository can assert that — a chart rendered alone has no sibling to collide
with. The parent's suite at step 9 is the only place that can. The measurement behind
this paragraph is recorded there and in the pull request that added this file, rather
than restated here. A version-pinned measurement written into a comment is a claim no
suite re-runs. This paragraph already lost one sentence for being unverifiable, and a
measured one that nothing re-checks goes stale the same way.

A TOGGLE GATES A RESOURCE; IT DOES NOT DIAGNOSE A MISSING PREREQUISITE. A toggle
set true on a cluster with no mariadb-operator renders cleanly and then fails at
apply with `no matches for kind MariaDB`, half-way through an install, naming a kind
rather than an operator somebody has to go and install. This partial is what makes
the refusal happen before anything is applied, with the operator's name in it.

WHAT IT PROVES, AND WHAT IT DOES NOT. `.Capabilities.APIVersions.Has` answers "is
this API registered on the target". It NEVER answers "is a controller running". A
cluster carrying mariadb-operator's CRDs with no operator pod renders, installs, and
then leaves the MariaDB object sitting there unreconciled while the pod beside it
crash-loops on a Secret that is never minted. The controller half is the preflight
Job `yadgarhq/platform` carries, and this chart does not carry one.

IT MAY ONLY EVER BE CALLED FROM BEHIND A DEFAULT-FALSE TOGGLE. `Has` is false for
every API group outside helm's built-in list whenever there is no cluster and no
`--api-versions`, so a check reachable at a chart's defaults refuses every offline
render — `helm lint --strict`, the shared `helm lint and render` hook, and every
bare `helm template` in the estate's suites. `database.create` defaults false, which
is what makes this legal here.

CALL IT WITH A DICT:

  {{- include "iam-db.require-api" (dict
        "context"    $
        "apiVersion" "k8s.mariadb.com/v1alpha1"
        "operator"   "mariadb-operator"
        "toggle"     "database.create") }}
*/}}
{{- define "iam-db.require-api" -}}
{{- $context := .context -}}
{{- if not ($context.Capabilities.APIVersions.Has .apiVersion) -}}
{{- fail (printf (join "" (list
      "iam-db: this render needs the API %s, which %s provides, and the target does not have it. "
      "%s is true, and that is what asked for it. Install %s in the target cluster, or set %s false. "
      "If you are rendering offline: helm does not populate .Capabilities.APIVersions with "
      "CRD-backed groups from anywhere but a live cluster, so pass --api-versions %s to render this."))
      .apiVersion .operator .toggle .operator .toggle .apiVersion) -}}
{{- end -}}
{{- end -}}
