# Architecture

## Product purpose

UnWeb is an authorised web application security assessment platform. Its main job is to help defenders discover exposed attack surface, identify likely vulnerabilities, validate suspected issues safely, explain impact, and support remediation and retesting.

The current code is an engineering foundation, not a complete vulnerability scanner. Existing passive observations and browser metadata are evidence inputs; they must not be presented as proof of exploitability.

## Intended assessment lifecycle

```text
Explicit authorisation and target scope
  -> scope validation (hostnames, schemes, ports, paths, time window, budgets)
  -> passive attack-surface discovery
  -> pages, routes, scripts, APIs, assets, technologies, headers and cookies
  -> passive security checks
  -> optional isolated browser evidence collection
  -> bounded low-impact active checks
  -> controlled non-destructive validation (only when explicitly approved)
  -> evidence-backed findings and confidence
  -> risk and impact explanation
  -> remediation guidance
  -> safe retest and closure evidence
```

Every stage must inherit the same scope and budget. Redirects, discovered hosts, API calls, browser requests, and any follow-up check must be re-authorised against that scope. The system must stop rather than expand scope automatically.

## Current implementation

The current API:
- normalises HTTP(S) URLs and validates public DNS destinations;
- connects to validated IP literals while preserving HTTP Host and TLS identity;
- follows bounded same-origin HTML links and records only observed page edges;
- extracts metadata, assets, technologies and bounded JavaScript route/framework/source-map clues;
- records passive response-header and cookie-attribute observations with cookie-value redaction;
- persists owner-scoped website scans, repository reports, browser jobs/results, target authorizations and audit events in single-instance SQLite;
- requires trusted reverse-proxy identity in production and uses Redis-backed shared per-user rate limits;
- supports DNS TXT target-control challenges, revocation and port/path scope checks;
- dispatches browser jobs through Redis Streams to a separate worker container, with worker-side origin/path checks and heartbeat monitoring;
- applies bounded concurrency, timeout, request and rate limits.

The current scanner is primarily a discovery and passive evidence collector. It does not yet run a comprehensive vulnerability test suite, validate exploit chains, test logged-in authorization boundaries, or establish that a target is vulnerable. A missing security header is a configuration observation whose risk depends on application context, not automatically a critical vulnerability.

## Optional browser worker

The Playwright engine is an API-managed asynchronous worker, isolated from the ingress-facing API:

```text
Authenticated owner submits a scoped browser job
  -> API validates HTTPS URL, DNS-verified target grant, path subset and request budget
  -> owner-scoped job record is persisted in SQLite
  -> Redis Streams carries the job ID to the single worker consumer
  -> worker reloads the job and rechecks target authorization
  -> Chromium launches in a fresh non-persistent context with its sandbox enabled
  -> request and WebSocket guards enforce exact origin and approved path prefixes
  -> bounded DOM, asset, network and runtime evidence is persisted to SQLite
  -> owner retrieves the result through authenticated API routes
```

The worker uses a loopback-only CONNECT proxy and revalidates public DNS before opening a socket to a validated IP literal. This is runtime observation. It does not submit test inputs or prove vulnerability. Any later browser-assisted active test must use the explicit scope engine, request budgets, non-destructive payload policy, and worker isolation described above.

The proxy denies non-CONNECT traffic and any host/port other than the initial target origin. Every allowed CONNECT resolves the hostname again, rejects the entire answer set if any address is non-public, and connects to a validated IP literal rather than allowing the browser to perform the destination DNS lookup. Redirects therefore have to pass through the same proxy before the browser can open the next TLS tunnel. Browser route interception is an additional application-level control, not the security boundary.

**Mandatory external controls:** run the image as a non-root user in a disposable container with Chromium sandboxing available; apply a per-job default-deny egress policy that allows only the validated public target IP address(es) on the target HTTPS port and DNS only through a resolver restricted to the target hostname; deny loopback, private, link-local, multicast, IPv6 ULA, cloud metadata, and all other destinations; and enforce CPU, memory, process, and wall-clock limits. A standard Docker bridge network is not enough. The CLI acknowledgement flag does not inspect or enforce those controls. Since response byte counts are based on declared Content-Length headers, they are not a hard transfer cap.

Cross-origin subresources are blocked, so pages that depend on third-party CSS, fonts, images, or scripts may render incompletely. The worker currently handles one unauthenticated HTTPS page per job. It does not click links, submit forms, use a saved browser profile, or perform active vulnerability validation. API-managed jobs are owner-scoped in SQLite, dispatched through a Redis Streams consumer group, revalidated against the owner's current DNS-verified target grant immediately before execution, and stored with bounded evidence. The API exposes job creation/status/cancellation endpoints and a worker-heartbeat health endpoint. The production Compose stack mounts the same persistent SQLite volume into the API and one browser worker; do not scale either service against this single-instance SQLite deployment. The worker remains dependent on externally enforced default-deny egress controls.

## Repository analysis implementation

The repository analyser is a separate local CLI path:

```text
Operator selects an authorised local checkout
  -> resolve and validate a directory or validate a bounded ZIP archive
  -> for ZIP input, reject traversal/absolute paths, symlinks, duplicate paths and oversized entries; extract candidate files into a temporary directory
  -> enumerate supported source/config files without following symlinks
  -> skip generated, dependency, and VCS directories
  -> enforce file-count, per-file, total-byte, and finding budgets
  -> run Python AST checks and cross-language/configuration lexical checks
  -> parse supported dependency manifests/lockfiles into an inventory
  -> redact credential-shaped evidence
  -> emit JSON with suspected status and explicit limitations
```

The local CLI supports local directories and bounded user-provided ZIP archives. The FastAPI application exposes ZIP upload and public-GitHub source ingestion: an operator supplies a canonical `https://github.com/{owner}/{repo}` URL, an optional branch/tag, and an explicit authorisation acknowledgement. UnWeb resolves the selected ref to a 40-character commit SHA before requesting the ZIP archive from GitHub; it disables environment proxy inheritance, does not follow arbitrary redirects, accepts the archive redirect only on `codeload.github.com` for the selected repository path, streams at most 50 MB to a temporary file, analyses it without executing code or installing dependencies, and deletes the archive. Reports are persisted under the authenticated owner in SQLite and retain immutable source commit identity. Private repositories, GitHub OAuth/App installation, PATs and remote clone are not implemented. A separate OSV API endpoint can look up advisories for exact resolved package coordinates, but GitHub ingestion does not automatically enrich every report with advisory results. Python AST checks cover selected dangerous-call patterns; selected manifest/lockfile parsers inventory dependency declarations and resolved versions. There is no control-flow, data-flow, inter-file reachability, or complete package vulnerability analysis.

## Finding and evidence model

A common finding is a structured record, not just a label or a scary severity badge. The current contract includes:
- stable check identifier and category;
- affected URL, method, parameter or component;
- observed evidence and source location;
- validation level (passive, low-impact active, controlled proof, or inconclusive);
- confidence and severity, kept separate;
- preconditions and potential impact;
- concise reproduction steps that remain within the approved scope;
- remediation recommendation and retest procedure;
- timestamps, scanner version, scope identifier and request-budget accounting.

A suspected issue that has not been safely verified must be labelled as suspected or inconclusive. Do not claim a successful exploit merely because a payload was sent or an unusual response appeared. Avoid storing credentials, session cookies, full personal data, or response bodies unless a specific approved test requires a minimal redacted evidence sample.

## Planned security coverage

The check catalogue will be based on the OWASP Web Security Testing Guide, OWASP Top 10 and OWASP API Security Top 10. Priorities include access control, authentication/session handling, security misconfiguration, injection indicators, unsafe input/output handling, sensitive data exposure, API authorization, unrestricted resource use, SSRF indicators, unsafe API consumption, and error handling.

Coverage must be explicit. A scanner result should say which checks ran, which were skipped, why they were skipped, and what the tool cannot determine. The presence of a category in the roadmap does not mean it is currently implemented.

## Safety and execution boundaries

- Require explicit authorisation and a declared scope before any active test.
- Default to passive mode. Active checks require a selected profile and explicit operator confirmation.
- Enforce host, port, path, redirect, request-count, concurrency, time, and response-size budgets outside the browser process as well as inside it.
- Use benign markers and owner-provided test data/accounts for verification.
- Never automatically perform destructive writes, denial-of-service tests, credential attacks, persistence, stealth/evasion, broad data extraction, or attempts to access cloud metadata/internal services.
- Keep browser and active-test workers isolated, unprivileged, disposable, and subject to external egress policy.
- Preserve concise redacted evidence and an audit trail; do not collect sensitive information just because it is technically accessible.
- Treat all automated findings as assessment evidence requiring context, not as an infallible security verdict.

## Persistence

The preview uses the Python standard library's SQLite driver. Owner-scoped scan payloads, repository reports, browser job state/results, target authorizations and local audit events are stored in SQLite; Redis Streams dispatches browser job IDs and Redis also provides shared rate limits. Production Compose mounts one persistent SQLite volume into one API and one browser worker. This is intentionally single-instance and is not a horizontally scalable database architecture. The path is configurable through `UNWEB_DB_PATH`. Local audit events are not tamper-proof or a replacement for an independently controlled append-only audit service.

## Roadmap

- **Foundation (implemented preview):** bounded same-origin crawler, passive response observations, common evidence schema, read-only repository analysis, OSV exact-version advisory lookup, route inventory/correlation, SARIF export, owner-scoped persistence, DNS TXT target grants, trusted-proxy identity integration, Redis shared rate limits, API-managed Redis Streams browser jobs, hardened container images, tests and CI.
- **Security assessment MVP (incomplete):** broader documented passive checks, explicit low-impact active checks, stronger finding validation and false-positive handling, complete retest workflow, and richer evidence/report lifecycle.
- **Correlation and validation engine (incomplete):** deeper language-aware/data-flow analysis, stronger dependency coverage, owner-provided test identities, safe input-validation checks, risk ranking and remediation workflows.
- **Production hardening (incomplete):** operator-supplied OIDC/SAML gateway, host/cloud default-deny egress enforcement, externally controlled append-only audit, off-host backup and recovery drills, deployment monitoring, independent SSRF/security review, and replacement of single-instance SQLite if multi-instance scale is required.
## Common finding and evidence contract

`backend/app/finding_schema.py` adapts website and repository findings into a common `security_findings` contract without removing the legacy source-specific `findings` arrays. IDs are deterministic for the same source, check, target, and location, so a finding can be correlated across repeat scans while evidence and severity evolve. The record keeps severity separate from confidence and carries a controlled validation state. Website checks report observed response facts; local source patterns remain suspected until separately validated. Location is represented as a URL for website findings or a repository path and optional line number for code findings. Impact and preconditions remain unset when the scanner has not established them.
## Static repository route inventory

The repository analyser extracts literal route declarations without executing source. Python decorators use the standard-library AST. JavaScript/TypeScript route calls are lexical and ignore comments and matches starting inside string literals. Go handler calls, Spring mapping annotations, PHP route calls and Ruby route declarations are conservative lexical patterns. Records include method, path, source file, line and syntax hint. Dynamic route construction, route registration by imported modules, middleware ordering, router composition and runtime deployment are not resolved. A 2,000-record cap is reported as truncation. This inventory is a prerequisite for later website/repository path correlation, not a vulnerability finding.
## Website-to-repository route correlation

`frontend/src/lib/correlation.ts` compares the website scan's fetched page paths (GET observations) and JavaScript route-reference clues with the repository report's static route inventory. The comparison normalises URL paths, strips queries/fragments and trailing slashes, supports common one-segment parameter syntaxes, and excludes conflicts when both HTTP methods are known. It reports exact/parameterised overlap, source locations, unmatched lists and truncation. Confidence is deliberately capped at medium for exact path+method overlap and low for parameterised or unknown-method overlap because the scan target and repository snapshot may not be the same deployed version. The feature does not infer reachability, authorisation, authentication, or exploitability, and unmatched records are not evidence of absence.
## Website scan authorisation acknowledgement

`ScanRequest.authorised` defaults to false and `POST /api/scans` rejects a request without an explicit true value before consuming scan capacity. The dashboard requires the operator to check the corresponding ownership/permission acknowledgement. This is not identity authentication or proof of ownership: an arbitrary API client can assert the boolean. A production service still needs authenticated operator identity, verified target ownership/permission, durable scope records (approved host/port/path/window), audit trails and enforced network policy. Current website crawling remains same-origin and bounded by page count, request size, concurrency, timeout and rate controls.
## Python dynamic SQL heuristic

The Python AST pass checks the first argument to `execute`, `executemany` and `executescript` for f-string interpolation, string `+`/`%` construction, or `.format()` calls. It deliberately avoids flagging a literal query passed separately from its bind parameters. It is a local syntactic indicator only: no taint tracking, variable propagation, interprocedural analysis, or runtime validation is performed, and findings remain suspected rather than confirmed SQL injection.
