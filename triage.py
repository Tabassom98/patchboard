"""Domain logic and persistence. No web framework required to test this module."""
import csv
import io
import json
import sqlite3
from datetime import date, datetime, timedelta, timezone

FIELDS = ['asset', 'owner', 'criticality', 'internet_exposed', 'vulnerability',
          'title', 'severity', 'known_exploited', 'observed_on']
STATES = ('open', 'in_progress', 'resolved', 'exception')
DEFAULT_WEIGHTS = (6, 12, 6, 20)


def connect(path):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.executescript('''
      CREATE TABLE IF NOT EXISTS assets (
        name TEXT PRIMARY KEY, owner TEXT NOT NULL,
        criticality INTEGER NOT NULL CHECK(criticality BETWEEN 1 AND 5),
        exposed INTEGER NOT NULL CHECK(exposed IN (0,1)));
      CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY, asset TEXT NOT NULL REFERENCES assets(name),
        vulnerability TEXT NOT NULL, title TEXT NOT NULL, severity REAL NOT NULL,
        exploited INTEGER NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'open', exception_until TEXT,
        UNIQUE(asset,vulnerability));
      CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY, finding_id INTEGER REFERENCES findings(id),
        happened_at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
        detail TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS imports (
        id INTEGER PRIMARY KEY, happened_at TEXT NOT NULL, row_count INTEGER NOT NULL,
        inserted INTEGER NOT NULL, updated INTEGER NOT NULL);
    ''')
    return db


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def audit(db, fid, action, detail, actor='local operator'):
    db.execute('INSERT INTO audit(finding_id,happened_at,actor,action,detail) VALUES(?,?,?,?,?)',
               (fid, now(), actor, action, detail))


def parse_csv(text):
    reader = csv.DictReader(io.StringIO(text.lstrip('\ufeff')))
    if reader.fieldnames != FIELDS:
        raise ValueError('Columns must be exactly: ' + ','.join(FIELDS))
    rows, errors, seen, assets = [], [], set(), {}
    for number, raw in enumerate(reader, 2):
        try:
            if None in raw or any(v is None for v in raw.values()):
                raise ValueError('wrong number of columns')
            r = {k: v.strip() for k, v in raw.items()}
            if any(not r[k] for k in FIELDS):
                raise ValueError('every column is required')
            if any(len(v) > 240 for v in r.values()):
                raise ValueError('field exceeds 240 characters')
            r['criticality'] = int(r['criticality'])
            if not 1 <= r['criticality'] <= 5:
                raise ValueError('criticality must be 1–5')
            r['severity'] = float(r['severity'])
            if not 0 <= r['severity'] <= 10:
                raise ValueError('severity must be 0–10 and finite')
            for flag in ('internet_exposed', 'known_exploited'):
                if r[flag] not in ('yes', 'no'):
                    raise ValueError(flag + ' must be yes or no')
                r[flag] = int(r[flag] == 'yes')
            observed = date.fromisoformat(r['observed_on'])
            if observed > date.today() or observed.isoformat() != r['observed_on']:
                raise ValueError('observed_on must be YYYY-MM-DD and not in the future')
            key = (r['asset'], r['vulnerability'])
            if key in seen:
                raise ValueError('duplicate asset/vulnerability pair in this file')
            metadata = (r['owner'], r['criticality'], r['internet_exposed'])
            if r['asset'] in assets and assets[r['asset']] != metadata:
                raise ValueError('conflicting asset metadata in this file')
            seen.add(key)
            assets[r['asset']] = metadata
            rows.append(r)
        except (ValueError, TypeError) as exc:
            errors.append(f'Row {number}: {exc}')
    if errors:
        raise ValueError('\n'.join(errors[:30]))
    if not rows:
        raise ValueError('The CSV has no findings.')
    if len(rows) > 5000:
        raise ValueError('At most 5,000 findings per import.')
    return rows


def import_csv(db, text):
    rows = parse_csv(text)  # Validate the whole batch before touching the database.
    inserted = updated = 0
    with db:
        for r in rows:
            prior = db.execute('SELECT * FROM findings WHERE asset=? AND vulnerability=?',
                               (r['asset'], r['vulnerability'])).fetchone()
            if prior and r['observed_on'] < prior['last_seen']:
                raise ValueError('Older scan rejected for ' + r['asset'] + '/' + r['vulnerability'])
            latest = db.execute('SELECT MAX(last_seen) FROM findings WHERE asset=?', (r['asset'],)).fetchone()[0]
            if latest and r['observed_on'] < latest:
                raise ValueError('Asset metadata cannot be replaced by an older scan: ' + r['asset'])
            db.execute('''INSERT INTO assets VALUES(?,?,?,?) ON CONFLICT(name) DO UPDATE SET
              owner=excluded.owner,criticality=excluded.criticality,exposed=excluded.exposed''',
                       (r['asset'], r['owner'], r['criticality'], r['internet_exposed']))
            if prior:
                state = 'open' if prior['state'] == 'resolved' else prior['state']
                db.execute('''UPDATE findings SET title=?,severity=?,exploited=?,last_seen=?,state=?
                              WHERE id=?''', (r['title'], r['severity'], r['known_exploited'],
                                              r['observed_on'], state, prior['id']))
                audit(db, prior['id'], 'scan observation', json.dumps(r, sort_keys=True))
                if state != prior['state']:
                    audit(db, prior['id'], 'reopened', 'Observed again after resolution')
                updated += 1
            else:
                cursor = db.execute('''INSERT INTO findings(asset,vulnerability,title,severity,
                  exploited,first_seen,last_seen) VALUES(?,?,?,?,?,?,?)''',
                                    (r['asset'], r['vulnerability'], r['title'], r['severity'],
                                     r['known_exploited'], r['observed_on'], r['observed_on']))
                audit(db, cursor.lastrowid, 'imported', json.dumps(r, sort_keys=True))
                inserted += 1
        db.execute('INSERT INTO imports(happened_at,row_count,inserted,updated) VALUES(?,?,?,?)',
                   (now(), len(rows), inserted, updated))
    return inserted, updated


def score(row, weights=DEFAULT_WEIGHTS):
    """A policy heuristic, not a probability or validated risk model. Range 0–116."""
    parts = {'severity': row['severity'] * weights[0],
             'exposure': row['exposed'] * weights[1],
             'asset importance': (row['criticality'] - 1) * weights[2],
             'known exploitation': row['exploited'] * weights[3]}
    return round(sum(parts.values()), 2), parts


def effective_state(row, today):
    if row['state'] == 'exception' and row['exception_until'] < today.isoformat():
        return 'exception_expired'
    return row['state']


def findings(db, today=None):
    today = today or date.today()
    result = []
    for row in db.execute('''SELECT f.*,a.owner,a.criticality,a.exposed FROM findings f
                             JOIN assets a ON a.name=f.asset'''):
        r = dict(row)
        r['score'], r['parts'] = score(r)
        r['effective_state'] = effective_state(r, today)
        days = 7 if r['score'] >= 85 else 30 if r['score'] >= 60 else 90
        r['due'] = (date.fromisoformat(r['first_seen']) + timedelta(days=days)).isoformat()
        r['actionable'] = r['effective_state'] not in ('resolved', 'exception')
        r['overdue'] = r['actionable'] and r['due'] < today.isoformat()
        result.append(r)
    return sorted(result, key=lambda r: (-r['score'], r['first_seen'], r['id']))


def update_finding(db, fid, state, note, until='', today=None):
    today = today or date.today()
    note = note.strip()
    if state not in STATES or not note or len(note) > 2000:
        raise ValueError('Choose a valid state and provide a note of 1–2,000 characters.')
    if state == 'exception':
        try:
            end = date.fromisoformat(until)
        except ValueError:
            raise ValueError('An exception needs an expiry date.') from None
        if not today <= end <= today + timedelta(days=90):
            raise ValueError('Exception expiry must be today through 90 days from today.')
    else:
        until = None
    with db:
        old = db.execute('SELECT state FROM findings WHERE id=?', (fid,)).fetchone()
        if old is None:
            raise ValueError('Finding not found.')
        db.execute('UPDATE findings SET state=?,exception_until=? WHERE id=?', (state, until, fid))
        audit(db, fid, 'workflow update', json.dumps({'from': old['state'], 'to': state,
                                                   'exception_until': until, 'note': note}))


def evaluation(rows):
    """Compare ranking behavior; this does not establish real-world effectiveness."""
    key = lambda r: (r['first_seen'], r['id'])
    baseline = sorted(rows, key=lambda r: (-r['severity'], *key(r)))
    variants = {'default': DEFAULT_WEIGHTS, 'no exposure weight': (6, 0, 6, 20),
                'double exploitation weight': (6, 12, 6, 40)}
    positions = {r['id']: i + 1 for i, r in enumerate(baseline)}
    reports = []
    for name, weights in variants.items():
        ranked = sorted(rows, key=lambda r: (-score(r, weights)[0], *key(r)))
        top = ranked[:5]
        base_ids = {r['id'] for r in baseline[:5]}
        overlap = len(base_ids & {r['id'] for r in top}) / max(1, len(top))
        reports.append({'name': name, 'weights': weights, 'overlap': overlap,
                        'ranked': [(r, score(r, weights)[0], positions[r['id']] - i - 1)
                                   for i, r in enumerate(ranked)]})
    return baseline, reports
