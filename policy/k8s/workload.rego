package k8s.workload

# Enforce workload baseline and hardened security defaults.
# Scoped exceptions are explicitly listed to keep debt visible.

workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}

# Workloads that are temporarily exempt from pod-level strict controls.
# Format: <Kind>/<name>
pod_security_exemptions := {
  "StatefulSet/postgres",
  "StatefulSet/redis",
  "StatefulSet/minio",
  "Deployment/mimir",
}

# Containers that are temporarily exempt from strict container-level controls.
# Format: <Kind>/<name>/<container>
container_security_exemptions := {
  "StatefulSet/minio/minio",
  "Deployment/mimir/mimir",
}

is_workload {
  input.kind
  workload_kinds[input.kind]
}

resource_name := name {
  name := object.get(input.metadata, "name", "<unknown>")
}

workload_id := id {
  id := sprintf("%s/%s", [input.kind, resource_name])
}

is_pod_security_exempt {
  pod_security_exemptions[workload_id]
}

containers[c] {
  is_workload
  input.kind == "CronJob"
  c := input.spec.jobTemplate.spec.template.spec.containers[_]
}

containers[c] {
  is_workload
  input.kind == "Job"
  c := input.spec.template.spec.containers[_]
}

containers[c] {
  is_workload
  input.kind != "Job"
  input.kind != "CronJob"
  c := input.spec.template.spec.containers[_]
}

container_id(c) := id {
  id := sprintf("%s/%s/%s", [input.kind, resource_name, c.name])
}

is_container_security_exempt(c) {
  container_security_exemptions[container_id(c)]
}

pod_spec := spec {
  input.kind == "CronJob"
  spec := input.spec.jobTemplate.spec.template.spec
}

pod_spec := spec {
  input.kind == "Job"
  spec := input.spec.template.spec
}

pod_spec := spec {
  input.kind != "Job"
  input.kind != "CronJob"
  spec := input.spec.template.spec
}

deny[msg] {
  c := containers[_]
  image := object.get(c, "image", "")
  endswith(lower(image), ":latest")
  msg := sprintf("%s/%s container %q uses mutable image tag ':latest'", [input.kind, resource_name, c.name])
}

deny[msg] {
  c := containers[_]
  image := object.get(c, "image", "")
  not contains(image, ":")
  msg := sprintf("%s/%s container %q image is missing an explicit tag", [input.kind, resource_name, c.name])
}

deny[msg] {
  c := containers[_]
  object.get(object.get(c, "securityContext", {}), "privileged", false)
  msg := sprintf("%s/%s container %q must not run privileged", [input.kind, resource_name, c.name])
}

deny[msg] {
  c := containers[_]
  not is_container_security_exempt(c)
  sc := object.get(c, "securityContext", {})
  object.get(sc, "allowPrivilegeEscalation", null) != false
  msg := sprintf("%s/%s container %q must set allowPrivilegeEscalation=false", [input.kind, resource_name, c.name])
}

deny[msg] {
  c := containers[_]
  not is_container_security_exempt(c)
  sc := object.get(c, "securityContext", {})
  object.get(sc, "readOnlyRootFilesystem", null) != true
  msg := sprintf("%s/%s container %q must set readOnlyRootFilesystem=true", [input.kind, resource_name, c.name])
}

deny[msg] {
  not is_pod_security_exempt
  sc := object.get(pod_spec, "securityContext", {})
  object.get(sc, "runAsNonRoot", null) != true
  msg := sprintf("%s/%s pod must set securityContext.runAsNonRoot=true", [input.kind, resource_name])
}

deny[msg] {
  not is_pod_security_exempt
  sc := object.get(pod_spec, "securityContext", {})
  seccomp := object.get(sc, "seccompProfile", {})
  object.get(seccomp, "type", "") != "RuntimeDefault"
  msg := sprintf("%s/%s pod must set securityContext.seccompProfile.type=RuntimeDefault", [input.kind, resource_name])
}

deny[msg] {
  c := containers[_]
  not object.get(object.get(c, "resources", {}), "requests", null)
  msg := sprintf("%s/%s container %q must define resources.requests", [input.kind, resource_name, c.name])
}

deny[msg] {
  c := containers[_]
  not object.get(object.get(c, "resources", {}), "limits", null)
  msg := sprintf("%s/%s container %q must define resources.limits", [input.kind, resource_name, c.name])
}

deny[msg] {
  c := containers[_]
  not object.get(c, "readinessProbe", null)
  msg := sprintf("%s/%s container %q must define readinessProbe", [input.kind, resource_name, c.name])
}

deny[msg] {
  c := containers[_]
  not object.get(c, "livenessProbe", null)
  msg := sprintf("%s/%s container %q must define livenessProbe", [input.kind, resource_name, c.name])
}
