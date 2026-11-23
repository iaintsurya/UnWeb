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

It applies file-count and byte budgets, skips common vendor/build/VCS folders and symlinks, and never executes repository code or makes network requests. Python dangerous-call checks use the standard-library AST; cross-language and configuration checks are lexical. Security findings are heuristic and have the state `suspected`; this does not provide data-flow/reachability analysis or complete SAST coverage. Dependency inventory records declared constraints and lockfile-resolved versions only; it does not query advisories or identify vulnerable versions. The CLI can safely inspect a user-provided ZIP archive with path-traversal, symlink, entry-count, file-size, and total-byte checks before temporary extraction. It still has no GitHub API integration, remote clone operation, website/API/dashboard integration, or advisory lookup. Tests use local temporary fixtures and ZIPs only.

## Safe validation policy

Default to passive mode. Active checks require explicit authorisation, scope validation and a bounded profile. Use benign markers, synthetic test records, and owner-provided test accounts. Do not automatically perform destructive writes, denial-of-service tests, credential attacks, persistence, stealth/evasion, broad data extraction, or attempts to access cloud metadata/internal services. High-impact techniques belong in a separately approved lab or manual assessment plan.

Every request—including redirects, browser subresources, API calls and validation probes—must stay within the approved target scope and resource budget. A browser proxy is not a substitute for operating-system/container/network egress controls.



## Implemented passive cookie observations

The current entry-response analysis inspects individual `Set-Cookie` headers for the `Secure`, `HttpOnly`, and `SameSite` attributes, including the unsafe `SameSite=None` without `Secure` combination. These are low-impact configuration observations, not proof that a cookie is an authentication credential or that a vulnerability is exploitable. Findings retain the cookie name and missing attribute only. Raw cookie values are held only long enough for in-memory analysis and are stripped before scan headers are returned, displayed, or persisted. If a response contains malformed cookie syntax, UnWeb skips that cookie rather than guessing.

## Roadmap principle

Prefer fewer checks with strong evidence, clear false-positive handling and useful remediation over a long list of weak signatures. UnWeb should say what it tested, what it found, what it did not test, and what it cannot prove.
