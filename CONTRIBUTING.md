# Contributing
- Discuss large changes in an issue before implementation.
- Never commit credentials, private scan data, or sensitive URLs.
- Add tests for URL policy, parser changes, and new detection rules.
- Label detections as observed or inferred; include evidence and confidence.
- Python: type hints, small modules, clear exceptions; Ruff-compatible formatting.
- TypeScript: strict mode, avoid `any`, use explicit API types.
- Do not add authentication bypass or exploitation features.
- Commit examples: `feat: add page relationship graph`, `fix: reject unsafe redirect`, `test: cover malformed HTML`.
- PR checklist: tests, docs, safety review, no secrets, frontend build.
