# Architecture and threat model

Browser → Flask routes → domain functions → SQLite.

The project separates HTTP concerns from import, score, workflow, and evaluation logic. Jinja templates render the interface; there is no JavaScript build pipeline or external asset dependency.

## Stored records

- Assets: stable name, team owner, importance, exposure.
- Findings: asset reference, scanner vulnerability label, title, severity, exploitation flag, observation dates, lifecycle state, exception expiry.
- Audit: finding reference, UTC timestamp, local actor label, action, JSON details.
- Imports: time, row count, inserted count, repeat count.

The database enforces finding identity with a unique constraint. Importing validates the file before opening a mutation transaction; database-stage failures roll back the transaction too. Older scans are rejected so they cannot overwrite newer context. Repeat imports do not duplicate findings, but do append observation events: this is deliberate evidence history, not byte-level idempotence.

An asset's owner and context describe its current state. They can affect several findings at once. Original context can be reconstructed from observation JSON, but the application does not yet provide a historical as-of ranking view. Same-day conflicting scans across separate files are not ordered beyond import order.

## Boundaries

The operator and local machine are trusted. CSV text is untrusted. Imports can change the queue and current asset metadata; the operator must choose the intended file. File contents are decoded and parsed, never executed or placed on disk as uploaded files.

SQL values use parameter binding. HTML templates retain automatic escaping, including notes and CSV text. POST operations require a session CSRF token. Cookies use HttpOnly and SameSite Strict, and host validation limits accepted hostnames. Response headers limit scripts, framing, and external resource loads. Request size and row counts are bounded. There is no CSV export, which avoids introducing spreadsheet-formula behavior through this feature.

These controls do not make the app production-ready. Anyone with access to the local database can modify history. There is no authentication, role separation, cryptographic audit integrity, rate limiting, backup management, or real exploit-feed verification. Changing the bind address to expose the Flask server is outside the intended deployment model. The process uses a random session key per start, so restarting invalidates existing form sessions.

## Lifecycle choices

Open, in progress, resolved, and exception are operator states. An expired exception is derived at read time; it does not create a scheduled audit event. An exception remains active on its expiry date and becomes actionable the next day. Resolution requires an explanation, but the tool cannot verify that the explanation is true. Exceptions record a decision, not proof that residual risk is acceptable.

## Known gaps worth investigating

Stable inventory IDs; service/port-level finding identity; missing-data states rather than forced binary flags; confidence and source freshness; historical context snapshots; concurrency behavior; independent review of policy weights; deployment with authenticated users. These are open design problems, not completed features.
