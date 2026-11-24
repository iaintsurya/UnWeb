# GitHub code-scanning integration

UnWeb can export repository assessments as SARIF 2.1.0. The export can be uploaded to the **repository being assessed** using GitHub code scanning.

## Manual upload workflow

1. Run an authorised repository analysis in UnWeb.
2. Select **Export SARIF** and save the file as `unweb.sarif`.
3. Add the SARIF file to the root of the repository being assessed and commit it to a branch.
4. Copy [the example workflow](../examples/github-actions/upload-unweb-sarif.yml) into that repository at `.github/workflows/upload-unweb-sarif.yml`.
5. Ensure GitHub code scanning is available for that repository and that Actions are allowed to use `security-events: write`.
6. Open **Actions → Upload UnWeb SARIF → Run workflow**. Keep the default `unweb.sarif` path or enter another repository-relative path.

The workflow validates that the input is a SARIF 2.1.0 JSON document before calling GitHub's maintained `upload-sarif` action. It uses a stable category so subsequent uploads update the same UnWeb analysis category rather than creating a new category for every run.

## Important interpretation notes

- Uploading a report does not independently verify a finding. UnWeb's repository indicators remain heuristic and `suspected`.
- The upload workflow runs in the target repository. Running it in the UnWeb source repository would publish results to UnWeb, not to the repository that was analysed.
- GitHub code-scanning availability and plan requirements depend on repository visibility and account settings.
- The SARIF file is committed to the target repository in this manual workflow. Review it for sensitive source evidence before committing; UnWeb redacts recognised secret values, but redaction is not guaranteed to catch every secret format.
- This workflow is manually triggered. It does not automatically fetch private repositories or run UnWeb analysis on every push.
