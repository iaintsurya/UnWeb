# UnWeb Security Assessment Model

## Mission

UnWeb helps owners and defenders find and fix web application weaknesses before attackers exploit them. It is an authorised assessment tool. It is not intended to break into arbitrary websites, harvest data, or perform uncontrolled exploitation.

## Assessment stages

1. **Authorise:** identify who approved the test and what targets, paths, ports, accounts, time window and techniques are in scope.
2. **Discover:** build an inventory of reachable pages, API routes, scripts, assets, forms, technologies and browser-observed requests.
3. **Check:** execute documented passive checks first, followed by explicitly enabled low-impact active checks.
4. **Validate:** use the minimum non-destructive evidence needed to distinguish a real weakness from a false positive. Use synthetic data and owner-provided test identities where authorization behavior must be compared.
5. **Report:** explain the affected component, evidence, confidence, potential impact, preconditions, and limitations.
6. **Remediate and retest:** provide actionable defensive guidance and repeat only the relevant bounded check.

## Finding states

- **Observed:** raw evidence exists, but no vulnerability conclusion has been established.
- **Suspected:** evidence is consistent with a weakness, but alternative explanations remain.
- **Validated:** a documented, non-destructive test confirmed the security property failed within the approved scope.
- **Inconclusive:** the check could not safely or reliably determine the result.
- **Not observed:** the check ran and did not observe the tested condition. This does not prove the application is free of the vulnerability class.
- **Not tested:** the check was skipped, unsupported, outside scope, or lacked prerequisites.

Confidence and severity are separate. A high-impact issue with weak evidence should not be reported as a confirmed critical vulnerability. Severity should consider impact, exploit preconditions, exposure, and available evidence.

## Minimum finding fields

A finding should carry: check ID, category, affected URL/component, method/parameter where relevant, observation time, evidence source, validation state, confidence, severity, preconditions, potential impact, bounded reproduction notes, remediation, retest steps, scanner version, scope ID, and request-budget usage.

Evidence should be minimal and redacted. Never store secrets, credentials, session cookies, or unnecessary personal data in reports.

## Initial coverage catalogue

Use established public references as a baseline:

- OWASP Web Security Testing Guide (WSTG): information gathering, configuration, identity, authentication, authorization, session management, input validation, error handling, cryptography, business logic, client-side and API testing.
- OWASP Top 10:2025: Broken Access Control, Security Misconfiguration, Software Supply Chain Failures, Cryptographic Failures, Injection, Insecure Design, Authentication Failures, Software or Data Integrity Failures, Security Logging and Alerting Failures, and Mishandling of Exceptional Conditions.
- OWASP API Security Top 10:2023: Broken Object Level Authorization, Broken Authentication, Broken Object Property Level Authorization, Unrestricted Resource Consumption, Broken Function Level Authorization, Unrestricted Access to Sensitive Business Flows, Server-Side Request Forgery, Security Misconfiguration, Improper Inventory Management, and Unsafe Consumption of APIs.

These references are coverage guidance, not claims about current UnWeb functionality. Every check needs its own implementation, fixtures, expected evidence, limitations and remediation.

## Implemented local repository-analysis preview

A first read-only repository analyser is available as a local CLI at `backend/app/repository_analysis.py`. It scans selected source and configuration files for:

- credential-like assignments, selected provider-token patterns, and private-key PEM markers (with values omitted/redacted);
- Python dynamic evaluation, shell-enabled subprocess calls, `os.system`, YAML loading without a visible SafeLoader, and pickle deserialization;
- disabled TLS certificate verification and wildcard CORS configuration;
- dependency inventory from npm package manifests/lockfiles, Python requirements and pyproject files, Cargo manifests/lockfiles, and Go module files.

It applies file-count, byte, and 5,000 dependency-record budgets (and marks the inventory when that cap is reached), handles deeply nested or wrong-shaped parser input without aborting the scan, skips common vendor/build/VCS folders and symlinks, and never executes repository code or makes network requests. Python dangerous-call checks use the standard-library AST; cross-language and configuration checks are lexical. Security findings are heuristic and have the state `suspected`; this does not provide data-flow/reachability analysis or complete SAST coverage. Dependency inventory records declared constraints and lockfile-resolved versions only; it does not query advisories or identify vulnerable versions. The CLI can safely inspect a user-provided ZIP archive with path-traversal, symlink, entry-count, file-size, and total-byte checks before temporary extraction. The React dashboard supports ZIP upload (`POST /api/repository-scans`) and public GitHub repository selection (`POST /api/github-repository-scans`). GitHub ingestion requires an explicit operator acknowledgement, accepts canonical HTTPS GitHub repository URLs only, resolves a branch/tag to an immutable commit SHA, disables ambient proxy configuration, restricts the archive redirect to `codeload.github.com` and the selected repository path, streams no more than 50 MB, applies repository concurrency/rate controls, deletes temporary archives, and persists the resulting report under the authenticated owner in SQLite (latest 100 per owner). The dashboard can reload saved reports and export JSON or SARIF 2.1.0. The GitHub integration is public-only: private repositories, OAuth/App installation, personal access tokens, webhook/PR integration, and advisory lookup are not implemented. The local CLI remains offline; only the GitHub API/archive ingestion route makes network requests. Tests use local fixtures and mocked GitHub HTTP responses; they do not download third-party repositories.

### Implemented passive HTTP response observations

The website response checks also inspect wildcard CORS origin values, permissive CSP script-source directives, version-like Server header values, and X-Powered-By disclosures. These are deliberately low-severity or informational observations: wildcard CORS does not by itself prove private-data exposure, a permissive CSP signal does not prove script execution, and technology/version disclosure does not prove that a component is vulnerable. Exact technology/version values are omitted from the generated evidence to avoid unnecessarily repeating fingerprint details. Operators should review the complete response policy and application context before treating any observation as a security issue.

## Safe validation policy

Default to passive mode. Active checks require explicit authorisation, scope validation and a bounded profile. Use benign markers, synthetic test records, and owner-provided test accounts. Do not automatically perform destructive writes, denial-of-service tests, credential attacks, persistence, stealth/evasion, broad data extraction, or attempts to access cloud metadata/internal services. High-impact techniques belong in a separately approved lab or manual assessment plan.

Every request—including redirects, browser subresources, API calls and validation probes—must stay within the approved target scope and resource budget. A browser proxy is not a substitute for operating-system/container/network egress controls.



## Implemented passive cookie observations

The current entry-response analysis inspects individual `Set-Cookie` headers for the `Secure`, `HttpOnly`, and `SameSite` attributes, including the unsafe `SameSite=None` without `Secure` combination. These are low-impact configuration observations, not proof that a cookie is an authentication credential or that a vulnerability is exploitable. Findings retain the cookie name and missing attribute only. Raw cookie values are held only long enough for in-memory analysis and are stripped before scan headers are returned, displayed, or persisted. If a response contains malformed cookie syntax, UnWeb skips that cookie rather than guessing.

## Roadmap principle

Prefer fewer checks with strong evidence, clear false-positive handling and useful remediation over a long list of weak signatures. UnWeb should say what it tested, what it found, what it did not test, and what it cannot prove.

## Implemented dependency advisory lookup

The API can query the public OSV batch endpoint for exact resolved versions in npm, PyPI, Go and crates.io. It accepts package coordinates only (not URLs), deduplicates package/version tuples, caps each request at 100 packages and the provider response at 2 MB, limits advisory records per package, and returns an allowlisted metadata subset. In production, the endpoint is authenticated through the trusted identity gateway and uses a shared Redis per-user rate limit; development uses an in-process limiter. No dependency is downloaded, installed, or executed. An empty OSV result is not proof that a dependency is secure; feed coverage and publication timing vary. The operator acknowledgement remains separate from authentication and does not prove permission.


## Initial redirect scope enforcement

The first website request is constrained to the origin in the submitted URL. Redirects on the initial response, later page requests, and JavaScript fetches must remain on that same scheme/host/port origin. A redirect to another public host is rejected rather than silently transferring the scan to a destination the operator did not submit. This is an origin boundary, not a substitute for a future explicit hostname/path/port scope model or external network egress controls.


## Additional passive header-value checks

The website response analyser now distinguishes missing security headers from selected ineffective values. It reports an `X-Content-Type-Options` value other than `nosniff`, an HTTPS HSTS header with a missing, ambiguous, invalid, or zero `max-age`, and an empty `Content-Security-Policy` header. These are bounded configuration observations only; they do not establish exploitability or assess the full quality of a CSP. A valid header value can still be insufficient for a particular application.

## Website path-scope enforcement

Website scan requests accept 1–20 approved absolute URL path prefixes. The default `/` retains the previous whole-origin behavior; narrower prefixes use segment-aware matching. The scanner rejects unsafe or ambiguous scope entries, including hostnames, query strings, fragments, control characters, backslashes, encoded separators, and dot segments. The approved paths are enforced before the initial network request and across discovered page links, redirects, and same-origin JavaScript fetches. The normalized prefixes are included in scan results. Path scope supplements the existing scheme/host/port origin boundary; it is not authentication, ownership verification, or external network egress enforcement.


## Trusted identity, owner isolation, and audit trail

The API can be deployed behind a trusted identity gateway. When `UNWEB_ENV=production`, startup fails unless `UNWEB_AUTH_PROXY_SECRET` is configured. The reverse proxy must authenticate the user, strip client-supplied `X-UnWeb-Auth-Token` and `X-UnWeb-Auth-User` headers, and inject the shared secret plus a stable user identifier. The API validates the secret with a constant-time comparison, validates the identifier format, and rejects missing or invalid identities on API routes. The backend must remain network-private behind the proxy; the shared secret is not a substitute for network isolation or TLS.

Persisted website scans are tagged with the authenticated owner ID. Scan history and scan detail/intelligence/sitemap/security/reconstruction endpoints query by both scan ID and owner ID, returning 404 for another user's scan. Existing SQLite databases are migrated with legacy rows assigned to the `local` owner. Scan retention is capped per owner so one user's activity does not evict another user's results. ZIP/GitHub repository analysis reports are still returned to the caller without being persisted.

Production rate-limit buckets are keyed by authenticated user identity in Redis using atomic Lua sliding windows and Redis server time, shared across API processes. If Redis becomes unavailable, scan and advisory endpoints fail closed with HTTP 503. The in-memory limiter is retained only for development/tests. The production Compose profile runs one API worker because SQLite persistence remains single-instance. Successful website scans, repository analyses, and advisory lookups write minimal owner-scoped audit events. The endpoint exposes only the authenticated user's events; the database keeps at most 1,000 events per owner. These local SQLite events are not tamper-proof and do not yet capture all rejected/failed requests. Forward security-relevant events to an independently controlled append-only log service for production.

This is an integration contract for an external identity provider/reverse proxy, not a built-in login, password-reset, MFA, OAuth, team, or role-management implementation. The operator acknowledgement fields remain acknowledgements only and do not prove target ownership or permission.


## Production container baseline and remaining external controls

The repository now includes a non-root API image, a non-root Nginx frontend image, and a production Compose stack. The API and frontend containers use read-only root filesystems, dropped Linux capabilities, no-new-privileges, bounded memory/CPU/PID settings, and only the API's data directory and Redis data directory are persistent. Redis is attached only to an internal Compose network. The API is not host-published; it is reachable only through the ingress network and the frontend reverse proxy. Production startup requires both the trusted identity secret and a healthy Redis service.

The ingress and egress Docker networks are external and must be created and secured by the operator. Attach only the trusted authentication gateway to ingress. Apply host/cloud firewall policy to the API's egress network: deny loopback, RFC1918/private, link-local, multicast, IPv6 ULA, cloud metadata and other infrastructure destinations; allow only the public HTTP/HTTPS destinations needed by the explicitly authorised target scopes and the required advisory provider. The Compose network itself does not implement a per-job firewall or dynamic destination allowlist. Do not interpret the deployment files as proof that external egress policy is active.

The Compose stack is intentionally single API instance because scan history, repository reports, browser-job state/results and audit events use SQLite. Redis provides shared rate limits and Redis Streams dispatches browser job IDs to the separate worker; the worker and API share the SQLite data volume. This is a single-consumer/single-instance design, not horizontally scalable distributed storage. Production deployment still requires an external OIDC/SAML identity gateway, host/cloud default-deny egress enforcement, external append-only audit logging, off-host backup and recovery drills, and independent security review. DNS TXT verification proves control of a hostname at verification time, not legal permission for every service behind it.


## DNS-verified target scope

Production website scans now require an owner-scoped target authorization created by a one-time DNS TXT challenge. The challenge stores only a token hash, expires after one hour, and can be consumed once. Verified grants expire after 30 days and can be revoked. The scan API checks the exact normalized hostname, approved port, and segment-aware subset of approved path prefixes before consuming scan capacity. Challenges are rate-limited through the same shared Redis infrastructure. This is stronger than a consent boolean but is not proof of legal permission for every service behind a domain, does not verify ownership of third-party SaaS infrastructure referenced by DNS, and does not replace a signed engagement record or external network firewall.


## Readiness and dependency health

The API exposes public liveness (`GET /api/health`) and readiness (`GET /api/health/ready`) endpoints; readiness checks SQLite and, in production, Redis. The production container healthcheck uses readiness. The browser-worker heartbeat endpoint (`GET /api/health/browser-worker`) is not in the API middleware's public health exemptions and therefore requires trusted identity when the production auth secret is configured. Health probes expose generic dependency state only; they do not prove that the external identity gateway or egress firewall is correctly configured.
