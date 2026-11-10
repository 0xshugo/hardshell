# Trivy diagnostic redaction regression and merge prevention

## Scope

Follow-up to [PR #36's unresolved P1 review](https://github.com/0xshugo/hardshell/pull/36#discussion_r4519088988).
The previous redactor did not recognize JSON-quoted secret keys. Short values could
therefore be serialized into `scanner_evidence.trivy.stderr_tail` in a failed scan
report. This is a reproducible disclosure path, not evidence that real credentials
were disclosed.

This change handles quoted and unquoted secret keys, escaped JSON keys and values,
single-quoted values, and complete JSON object/array values. When a recognized secret
value is malformed or truncated, its remaining suffix is omitted rather than guessed.
Redaction still occurs before the UTF-8 byte limit. A reused scanner now clears its
previous evidence before starting or communicating with a new subprocess.

Free-form log redaction remains heuristic. This fix does not claim that arbitrary
unlabelled, encoded, or otherwise unrecognized credentials can be safely published.
Do not use a successful unit test as proof that production logs contain no secrets.

## Verification

- Base: `b99f5e4f6c2d4f99cdbf1dccea9ba1a128ddcce2`.
- Before the fix: 41 of the initial 45 new regression cases failed.
- After the fix: 47 new regression cases pass, including the two evidence reuse cases.
- Scanner failure and redaction tests: 63 pass.
- Full suite: 216 pass, with one pre-existing `datetime.utcnow()` deprecation warning.
- Ruff, sdist/wheel build, and whitespace validation pass.
- Independent code review found the evidence reuse issue; the correction is included.

Dependencies were installed with `uv sync --locked --all-extras`. The test executor
has a SOCKS proxy configured but the project does not depend on `socksio`. An ordinary
test invocation fails one unrelated funding test on both the base and changed code.
The full passing run removed proxy variables **only in the test process** and replaced
`socket.socket.connect` and `connect_ex` with a function that raises. No real network
connection was allowed by that test harness. No lockfile or production setting changed.

```sh
uv run --locked pytest -q tests/test_trivy_redaction.py tests/test_scan_failures.py
uv run --locked ruff check src tests
uv build
git diff --check
```

## Merge prevention: configuration still required

The `protect-main` ruleset inspected on 2026-11-10 requires `lint-and-test`, prevents
branch deletion and non-fast-forward updates, and has no bypass actors. It does not
require review approval or resolution of review conversations. Thus passing tests
alone do not block an unresolved P1 finding.

Recommended changes, pending explicit repository-administration approval:

1. Require pull requests and resolution of every review conversation before merge.
2. Require an independent approval for the latest change; dismiss stale approvals
   when new commits arrive. Confirm a reviewer other than the author is available
   before enabling a one-approval requirement.
3. Require the branch to be up to date with the target and keep `lint-and-test`
   required. The new regression tests run in that existing required job.
4. Retain no bypass actors. Treat a review's “completed” state as distinct from a
   successful review with all findings resolved.

This PR does not change repository rules, merge itself, deploy to the VPS, inspect
real secret values, rotate credentials, or remove historical reports. Deployment
and any incident-response action require separate authorization and verification.
