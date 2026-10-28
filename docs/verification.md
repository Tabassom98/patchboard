# Verification record

Flask 3.1.2 was installed by the user after the creation environment blocked its download. The full test suite then ran with the installed dependency and a workspace-local temporary directory.

All 10 domain tests passed. They cover score extrema, malformed numeric inputs, batch validation, duplicate/conflicting records, repeat identity, transaction rollback on stale scans, reopening, exception expiry, workflow validation, and the reproducible sample ranking. Python compilation checks also passed.

All three Flask integration tests passed: empty routes and missing findings, CSRF rejection (including a Unicode token), and CSV import followed by a workflow update and HTML escaping. Total: 13 passing tests, none skipped. Initial browser access to an agent-started server failed; the user then started the server and browser access succeeded.

## Browser checks — October 28, 2026

Using the real Flask app at 127.0.0.1:5050:

- Empty queue rendered, then scan 01 imported as ten new findings.
- Search for student-portal returned one finding.
- Resolution and an investigation note saved to the history.
- Scan 02 added one finding and updated four observations; the resolved portal finding reopened with its first-seen date retained and a reopening event recorded.
- An exception without an expiry produced a validation message. A valid exception left the actionable queue and appeared under the active-exception filter. The finding was returned to open after testing.
- A malformed CSV header was rejected with an explanatory message.
- The ranking study displayed all three policy variants and current actionable findings.
- Dashboard screenshots were inspected at the default width, 390 pixels, and 1280 pixels. At phone width the page did not overflow horizontally; tables have their own horizontal scroll area.

A long floating-point decimal was found in the score component display. The template now formats components to two decimal places, and the integration test verifies `+48.60`. All 13 tests passed again after the change. The user's running Flask process caches the old template, so a restart is needed before that display fix can be visually rechecked.

The local demo database contains 11 synthetic findings and explicitly labeled browser-QA notes. It is excluded from the downloadable archive. No full accessibility audit, production deployment, real scanner integration, or external reviewer experiment is claimed.

## Compact workbench revision

The revised queue adds owner and signal filters, severity/deadline sorting, priority bands, observation ages, days until deadline, and movement versus the severity-only baseline. The side panel displays the latest import, upward ranking shifts, and readable recent workflow notes. The local briefing uses fixed rules and current actionable findings across the workspace; it is independent of table filters, does not use a language model, and makes no external service calls.

All 15 automated tests passed, including two new tests for the briefing, team/signal filters, severity ordering, empty results, state-aware summary updates, and note escaping. After a user restart, browser checks confirmed overdue filtering (two findings), Research support filtering with severity ordering (three findings), and correct loaded briefing/import/decision information. Layouts were inspected at 1440 and 390 pixels with no document-wide horizontal overflow. The downloadable archive was refreshed; runtime databases and installed packages are excluded.

Run both test files after installing requirements; confirm no tests are skipped before relying on the web verification. For manual review, use a narrow viewport, keyboard navigation, a rejected CSV, both sample scans, an exception, and an escaped HTML-like note. Check that each response and ranking explanation is readable.
