package k8s.availability

# Environment-specific availability/disruption policies.
# Staging is maintenance-friendly; production is strict no-downtime for API rollouts.

is_staging_api {
  input.kind == "Deployment"
  object.get(input.metadata, "name", "") == "secure-observable-api"
  object.get(object.get(input.metadata, "labels", {}), "app.kubernetes.io/environment", "") == "staging"
}

is_production_api {
  input.kind == "Deployment"
  object.get(input.metadata, "name", "") == "secure-observable-api"
  object.get(object.get(input.metadata, "labels", {}), "app.kubernetes.io/environment", "") == "production"
}

is_staging_pdb(name) {
  input.kind == "PodDisruptionBudget"
  object.get(input.metadata, "name", "") == name
  object.get(object.get(input.metadata, "labels", {}), "app.kubernetes.io/environment", "") == "staging"
}

is_production_pdb(name) {
  input.kind == "PodDisruptionBudget"
  object.get(input.metadata, "name", "") == name
  object.get(object.get(input.metadata, "labels", {}), "app.kubernetes.io/environment", "") == "production"
}

deny[msg] {
  is_staging_api
  object.get(input.spec, "replicas", 0) < 2
  msg := "staging API must run at least 2 replicas"
}

deny[msg] {
  is_staging_api
  ru := object.get(object.get(input.spec, "strategy", {}), "rollingUpdate", {})
  object.get(ru, "maxUnavailable", "") != 1
  msg := "staging API must set rollingUpdate.maxUnavailable=1"
}

deny[msg] {
  is_staging_api
  ru := object.get(object.get(input.spec, "strategy", {}), "rollingUpdate", {})
  object.get(ru, "maxSurge", "") != 1
  msg := "staging API must set rollingUpdate.maxSurge=1"
}

deny[msg] {
  is_staging_pdb("secure-observable-api")
  object.get(input.spec, "maxUnavailable", "") != 1
  msg := "staging API PDB must set maxUnavailable=1"
}

deny[msg] {
  is_staging_pdb("postgres")
  object.get(input.spec, "maxUnavailable", "") != 1
  msg := "staging postgres PDB must set maxUnavailable=1"
}

deny[msg] {
  is_staging_pdb("redis")
  object.get(input.spec, "maxUnavailable", "") != 1
  msg := "staging redis PDB must set maxUnavailable=1"
}

deny[msg] {
  is_production_api
  object.get(input.spec, "replicas", 0) < 3
  msg := "production API must run at least 3 replicas"
}

deny[msg] {
  is_production_api
  ru := object.get(object.get(input.spec, "strategy", {}), "rollingUpdate", {})
  object.get(ru, "maxUnavailable", "") != 0
  msg := "production API must set rollingUpdate.maxUnavailable=0"
}

deny[msg] {
  is_production_api
  ru := object.get(object.get(input.spec, "strategy", {}), "rollingUpdate", {})
  object.get(ru, "maxSurge", "") != 1
  msg := "production API must set rollingUpdate.maxSurge=1"
}

deny[msg] {
  is_production_api
  object.get(input.spec, "minReadySeconds", 0) < 30
  msg := "production API must set minReadySeconds>=30"
}

deny[msg] {
  is_production_pdb("secure-observable-api")
  object.get(input.spec, "minAvailable", "") != 2
  msg := "production API PDB must set minAvailable=2"
}

deny[msg] {
  is_production_pdb("postgres")
  object.get(input.spec, "minAvailable", "") != 1
  msg := "production postgres PDB must set minAvailable=1"
}

deny[msg] {
  is_production_pdb("redis")
  object.get(input.spec, "minAvailable", "") != 1
  msg := "production redis PDB must set minAvailable=1"
}
