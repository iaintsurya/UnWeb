# UnWeb threat model

## Scope

UnWeb is a bounded, owner-authorised passive assessment service. It accepts website URLs, bounded ZIP archives, public GitHub repository references, and exact dependency coordinates. It stores reports and browser-job state in owner-scoped SQLite and uses Redis for shared rate limits and browser-job dispatch.

This document describes the implemented trust boundaries and the controls that remain external deployment responsibilities. It is not an independent penetration test.

## Assets

- Authenticated user identity and owner-scoped scan, report, target-grant, audit, and browser-job records.
- Target URLs, repository source, source locations, dependency coordinates, findings, and generated evidence.
- Proxy authentication secret and gateway-injected identity headers.
- SQLite and Redis data volumes.
- Browser-worker process, Chromium state, and outbound network access.

## Trust boundaries

1. **Identity gateway → frontend/API:** the gateway must authenticate the user, strip client-supplied identity headers, and inject the shared secret plus stable subject ID.
2. **API → target network:** the API performs scheme, origin, DNS, IP, redirect, timeout, response-size, and content-type checks. Host/cloud egress filtering remains the independent boundary.
3. **API → repository input:** ZIP archives and GitHub archives are bounded, extracted into temporary storage, checked for traversal/symlink/size limits, and analyzed without executing repository code.
4. **API → Redis:** production rate limits and browser dispatch depend on Redis availability; production startup fails when Redis is not configured.
5. **API/browser worker → SQLite:** the deployment is single-instance. Both services share the data volume and must not be scaled independently against one SQLite file.
6. **Browser worker → target:** worker requests are constrained by exact HTTPS origin, approved path prefixes, validated public IP literals, request limits, and a separate egress network. The external firewall is still mandatory.

## Threats and controls

| Threat | Implemented control | Residual requirement |
|---|---|---|
| IDOR/cross-owner reads | Owner ID is attached to scan, report, target, audit, and browser-job queries | Test the deployed gateway identity mapping and keep database access private |
| SSRF to private infrastructure | Global-IP checks, DNS validation, IP-pinned connections, redirect revalidation, origin/path checks | Independently enforce host/cloud default-deny egress |
| DNS rebinding | Resolve and validate before connecting to validated IP literals | Network policy must prevent alternate egress paths |
| ZIP traversal/bomb | Entry/path/symlink/file/byte/record limits and temporary cleanup | Keep upload proxy/body limits aligned with API limits |
| Secret leakage in reports | URL/header/evidence/reconstruction redaction | Treat logs, backups, and external audit sinks as sensitive |
| Browser job starvation | Per-owner/global pending caps, terminal retention, pending-aware stream trimming | Monitor backlog and worker heartbeat; verify Redis persistence |
| Malicious repository execution | Static parsing only; no clone, install, or source execution | Run analysis in a constrained service and protect the host filesystem |
| Header spoofing | Constant-time proxy-secret check and strict identity format | Gateway must strip inbound spoofed headers and be the only public path |
| Data loss | SQLite online backup and explicit restore utility | Perform off-host backups and scheduled isolated restore drills |

## Out of scope

UnWeb does not implement a built-in identity provider, legal ownership verification for every target, target-specific host/cloud egress enforcement, tamper-proof external audit storage, active exploit validation, destructive checks, data-flow SAST, or a complete SCA product.

## Release decision

Code and local validation are not equivalent to production readiness. A deployment is not ready for public multi-tenant use until the identity gateway, egress policy, backup destination, monitoring, external audit retention, branch protection, and independent security review are configured and verified by the operator.
