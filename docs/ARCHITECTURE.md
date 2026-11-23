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
- records passive response-header observations;
- saves scan results in single-instance SQLite;
- applies in-process concurrency, timeout and rate limits.

The current scanner is primarily a discovery and passive evidence collector. It does not yet run a comprehensive vulnerability test suite, validate exploit chains, test logged-in authorization boundaries, or establish that a target is vulnerable. A missing security header is a configuration observation whose risk depends on application context, not automatically a critical vulnerability.

## Optional browser worker

The Playwright engine is a separate CLI path, not an API dependency:

```text
Operator launches one disposable, non-root worker
  -> HTTPS target URL normalisation and public DNS validation
  -> loopback-only CONNECT proxy starts
  -> Chromium launches with its sandbox enabled and proxy configured
  -> fresh non-persistent context (downloads off, service workers blocked)
  -> context route guard permits only the target HTTPS origin
  -> CONNECT proxy revalidates DNS and opens a socket to a validated IP literal
  -> one DOM-ready render (request/time budgets)
  -> bounded DOM/style and network metadata report (query strings omitted)
  -> browser, context, proxy and process exit
```

This is runtime observation. It does not submit test inputs or prove vulnerability. Any later browser-assisted active test must use the explicit scope engine, request budgets, non-destructive payload policy, and worker isolation described above.

The proxy denies non-CONNECT traffic and any host/port other than the initial target origin. Every allowed CONNECT resolves the hostname again, rejects the entire answer set if any address is non-public, and connects to a validated IP literal rather than allowing the browser to perform the destination DNS lookup. Redirects therefore have to pass through the same proxy before the browser can open the next TLS tunnel. Browser route interception is an additional application-level control, not the security boundary.

**Mandatory external controls:** run the image as a non-root user in a disposable container with Chromium sandboxing available; apply a per-job default-deny egress policy that allows only the validated public target IP address(es) on the target HTTPS port and DNS only through a resolver restricted to the target hostname; deny loopback, private, link-local, multicast, IPv6 ULA, cloud metadata, and all other destinations; and enforce CPU, memory, process, and wall-clock limits. A standard Docker bridge network is not enough. The CLI acknowledgement flag does not inspect or enforce those controls. Since response byte counts are based on declared Content-Length headers, they are not a hard transfer cap.

Cross-origin subresources are blocked, so pages that depend on third-party CSS, fonts, images, or scripts may render incompletely. The worker currently handles one unauthenticated HTTPS page per process. It does not click links, submit forms, use a saved browser profile, or write scan output to SQLite. It is intentionally not callable from the API until UnWeb has a durable job queue and a separately managed worker pool with enforceable per-job network policy.

## Finding and evidence model (planned)

A finding should be a structured record, not just a label or a scary severity badge. The planned record includes:
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

The preview uses the Python standard library's SQLite driver. Scan payloads are stored as JSON with indexed summary columns; the newest 250 results are retained by default. This avoids requiring a separate database service for local use. It is a single-instance development store, not a horizontally scalable production database. The path is configurable through `UNWEB_DB_PATH`.

Before multi-user or enterprise use, storage must evolve to support authenticated ownership, job state, immutable audit records, evidence retention/redaction policies, and safe multi-instance concurrency.

## Roadmap

- **Foundation (current):** bounded crawler, observed page graph, SQLite scan history, JavaScript clues, passive security-header observations, optional isolated browser-worker prototype, tests and CI.
- **Security assessment MVP:** scope/consent model, target inventory, structured findings/evidence, passive checks, explicit low-impact active checks, reports and retesting.
- **Validation engine:** authorization testing using owner-provided test identities, safe input-validation checks, browser-assisted runtime evidence, API-focused checks, risk ranking, and remediation workflows.
- **Production hardening:** authentication, shared rate limits, durable worker queue, external network policy enforcement, audit retention, role separation and independent security review.
