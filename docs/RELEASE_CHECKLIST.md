# Release checklist

Use this checklist for every release. A checked local test does not prove that external deployment controls are configured.

## Code and CI

- [ ] Backend tests pass under the supported Python runtime.
- [ ] Frontend build and tests pass under the declared Node engine.
- [ ] `python -m compileall` and `git diff --check` pass.
- [ ] `npm audit` and `pip-audit` are reviewed.
- [ ] CodeQL and all required GitHub checks are green on the release commit.
- [ ] Production Compose configuration validates.
- [ ] API, frontend, and browser-worker images build and run.
- [ ] Production smoke tests wait for readiness, verify authentication, and always tear down.

## Security

- [ ] Identity gateway authenticates every frontend/API request.
- [ ] Gateway strips client identity headers and injects trusted values.
- [ ] API is not publicly reachable except through the gateway.
- [ ] Host/cloud egress policy independently blocks internal and metadata destinations.
- [ ] Owner-isolation, target-grant, IDOR, SSRF, redirect, ZIP, and browser-scope tests pass.
- [ ] Browser worker heartbeat and queue-backlog monitoring are configured.
- [ ] External append-only audit retention is configured if required by the deployment.
- [ ] Independent security review is complete.

## Data resilience

- [ ] Off-host SQLite backups are scheduled and encrypted/protected.
- [ ] Redis persistence/backup policy is documented.
- [ ] Restore drill passes in an isolated environment.
- [ ] RPO/RTO, rollback image, and operator ownership are documented.

## Branch and release governance

- [ ] Release branch is based on current `main`.
- [ ] Open PRs and Dependabot updates have a disposition.
- [ ] Main branch protection and required checks are verified through authenticated GitHub settings access.
- [ ] Release notes identify passive observations and known limitations honestly.

## Status definitions

- **Code complete:** repository changes and local tests are complete.
- **CI verified:** the release commit has passed required remote CI and CodeQL.
- **Deployment ready:** external identity, egress, backup, monitoring, and rollback controls are configured and verified.
- **Production ready:** deployment controls and independent security review are complete.
