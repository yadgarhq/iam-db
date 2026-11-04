{{/*
THE APP ACCOUNT'S CONNECTION CAP, COMPUTED IN ONE PLACE (yaadgaar #411, ADR-1142 rule 6).

  (max(autoscaling.maxReplicas, replicaCount) + maxSurge) x database.maxConnections + 1

`templates/app-account.yaml` writes it into the User and `templates/render-checks.yaml`
bounds it, and both call this, so the two cannot disagree.

THE MAX IS TAKEN WHATEVER `autoscaling.enabled` SAYS. That is the fail-closed choice:
the cap covers the KEDA ceiling even before autoscaling is turned on.

`maxSurge` IS READ FROM `rollingUpdate.maxSurge`, which is an OPEN map, so this reads
every shape Kubernetes accepts and refuses the rest:
  - absent: Kubernetes' own default, 25%;
  - "N%": rounded UP against the replica count, as the Deployment controller rounds a
    surge;
  - a whole number: as written.
A word, a digit string, a fraction or a negative number is refused here, naming the
key, because `int64` would turn it into 0 without a word and undercount the cap.

The `+ 1` is one connection of headroom over the pool arithmetic.

NO INPUT MAY WRAP (int64). The pod count and the result are held at or below
2147483647, the int32 ceiling of a replica count, and the product is checked BEFORE the
multiplication, by division, so an overflow cannot wrap into a small number that then
passes the engine bound. The replica counts themselves are refused above 2147483647 by
`templates/render-checks.yaml` in the same render, so a percentage surge multiplies at
most 2147483647 by 999, which int64 holds.
`autoscaling` is read only when it is a map; `templates/render-checks.yaml` refuses any
other shape by name, and that refusal fails the render whichever template runs first.
*/}}
{{- define "iam-db.appMaxUserConnections" -}}
{{- $v := .Values -}}
{{- $maxReplicas := 0 -}}
{{- if kindIs "map" $v.autoscaling -}}
{{- $maxReplicas = int64 $v.autoscaling.maxReplicas -}}
{{- end -}}
{{- $replicas := max (int64 $v.replicaCount) $maxReplicas -}}
{{- $limit := 2147483647 -}}
{{- $overflow := join "" (list
      "iam-db: the app account's maxUserConnections, (max(autoscaling.maxReplicas, "
      "replicaCount) + rollingUpdate.maxSurge) x database.maxConnections + 1, would exceed "
      "2147483647 at these values, and the arithmetic is refused before it can wrap. Lower "
      "the replica, surge or pool knobs.") -}}

{{- $rolling := $v.rollingUpdate | default dict -}}
{{- if not (kindIs "map" $rolling) -}}
{{- fail (printf "iam-db: `rollingUpdate` must be a map and is %s (%s)." (kindOf $rolling) (toJson $rolling)) -}}
{{- end -}}
{{- $surge := 0 -}}
{{- if not (hasKey $rolling "maxSurge") -}}
{{- $surge = div (add (mul $replicas 25) 99) 100 -}}
{{- else -}}
{{- $raw := $rolling.maxSurge -}}
{{- $read := false -}}
{{- if kindIs "string" $raw -}}
{{- if regexMatch "^(0|[1-9][0-9]{0,2})%$" $raw -}}
{{- $surge = div (add (mul $replicas (trimSuffix "%" $raw | int64)) 99) 100 -}}
{{- $read = true -}}
{{- end -}}
{{- else if or (kindIs "float64" $raw) (kindIs "int64" $raw) (kindIs "int" $raw) -}}
{{- if and (ge (float64 $raw) 0.0) (lt (float64 $raw) 2147483648.0) (eq (floor (float64 $raw)) (float64 $raw)) -}}
{{- $surge = int64 $raw -}}
{{- $read = true -}}
{{- end -}}
{{- end -}}
{{- if not $read -}}
{{- fail (printf (join "" (list
      "iam-db: `rollingUpdate.maxSurge` must be a whole number of at least 0 or a "
      "percentage such as \"25%%\", and is %s (%s). `database.create` is true, so the "
      "chart computes the app account's `maxUserConnections` from it, and a value it "
      "cannot read would undercount that cap."))
      (kindOf $raw) (toJson $raw)) -}}
{{- end -}}
{{- end -}}
{{- $pods := add $replicas $surge -}}
{{- $pool := int64 $v.database.maxConnections -}}
{{- if gt $pods $limit -}}
{{- fail $overflow -}}
{{- end -}}
{{- if and (gt $pool 0) (gt $pods (div (sub $limit 1) $pool)) -}}
{{- fail $overflow -}}
{{- end -}}
{{- add 1 (mul $pods $pool) -}}
{{- end -}}
