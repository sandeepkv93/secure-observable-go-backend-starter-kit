package k8s.workload

# Enforce baseline workload policies on rendered Kubernetes manifests.

workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}

is_workload {
  input.kind
  workload_kinds[input.kind]
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

resource_name := name {
  name := object.get(input.metadata, "name", "<unknown>")
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
  object.get(object.get(c, "securityContext", {}), "allowPrivilegeEscalation", false)
  msg := sprintf("%s/%s container %q must set allowPrivilegeEscalation=false", [input.kind, resource_name, c.name])
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
