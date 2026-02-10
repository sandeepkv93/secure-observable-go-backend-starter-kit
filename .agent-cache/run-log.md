# Run Log

- Recon captured branch/head/status and rate limiter failure mode hardcoding in `internal/di/providers.go`.
- Baseline tests passed.
- Added per-scope outage policy config and validation.
- Wired modes to global/auth/forgot/route policies.
- Added DI tests for fail-open/fail-closed behavior on Redis outage.
- Added config test for valid/invalid outage policy values.
- Updated README and .env example.
- Post-change tests passed.
