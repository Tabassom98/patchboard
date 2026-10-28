"""Local, single-operator demo. Run: python app.py"""
import os
import json
import secrets
from contextlib import closing
from datetime import date
from pathlib import Path

from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from triage import connect, evaluation, findings, import_csv, update_finding


def create_app(database=None):
    app = Flask(__name__)
    app.secret_key = secrets.token_hex(32)
    app.config.update(MAX_CONTENT_LENGTH=2 * 1024 * 1024,
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict',
                      TRUSTED_HOSTS=['127.0.0.1', 'localhost'])
    app.config['DATABASE'] = database or str(Path(__file__).with_name('patchboard.db'))
    with closing(connect(app.config['DATABASE'])) as db:
        pass

    @app.before_request
    def protect_local_demo():
        # Host validation and a per-session token protect the local write forms.
        session.setdefault('csrf', secrets.token_hex(32))
        if request.method == 'POST' and not secrets.compare_digest(
                request.form.get('csrf', '').encode('utf-8'), session['csrf'].encode('utf-8')):
            abort(400, 'Form expired. Reload the page and try again.')

    @app.after_request
    def headers(response):
        response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        return response

    @app.context_processor
    def context():
        return {'today': date.today().isoformat()}

    @app.get('/')
    def index():
        with closing(connect(app.config['DATABASE'])) as db:
            all_rows = findings(db)
            latest_scan = db.execute('SELECT * FROM imports ORDER BY id DESC LIMIT 1').fetchone()
            recent = [dict(r) for r in db.execute('''SELECT a.*, f.asset, f.vulnerability FROM audit a
                JOIN findings f ON f.id=a.finding_id WHERE a.action IN ('workflow update','reopened')
                ORDER BY a.id DESC LIMIT 5''')]
        for event in recent:
            if event['action'] == 'workflow update':
                data = json.loads(event['detail'])
                event['summary'], event['label'] = data.get('note', ''), data.get('to', '').replace('_', ' ')
            else:
                event['summary'], event['label'] = event['detail'], 'reopened'
        query = request.args.get('q', '').strip().lower()
        state = request.args.get('state', 'actionable')
        focus, owner, order = (request.args.get(k, d) for k, d in [('focus','all'),('owner',''),('sort','priority')])
        active = [r for r in all_rows if r['actionable']]
        severity_order = sorted(active, key=lambda r: (-r['severity'], r['first_seen'], r['id']))
        baseline_ranks = {r['id']: n for n, r in enumerate(severity_order, 1)}
        active_ranks = {r['id']: n for n, r in enumerate(active, 1)}
        for r in all_rows:
            r['movement'] = baseline_ranks.get(r['id'], 0) - active_ranks.get(r['id'], 0)
            r['age'] = (date.today() - date.fromisoformat(r['first_seen'])).days
            r['due_delta'] = (date.fromisoformat(r['due']) - date.today()).days
            r['band'] = 'urgent' if r['score'] >= 85 else 'high' if r['score'] >= 60 else 'routine'
        rows = [r for r in all_rows if query in ' '.join(
            str(r[k]) for k in ('asset', 'vulnerability', 'title', 'owner')).lower()]
        rows = [r for r in rows if state == 'all' or
                (state == 'actionable' and r['actionable']) or r['effective_state'] == state]
        rows = [r for r in rows if not owner or r['owner'] == owner]
        rows = [r for r in rows if focus == 'all' or (focus == 'overdue' and r['overdue']) or
                (focus == 'exploited' and r['exploited']) or (focus == 'exposed' and r['exposed'])]
        sorters = {'severity': lambda r: (-r['severity'],r['id']), 'deadline': lambda r: (r['due'],-r['score'],r['id']),
                   'priority': lambda r: (-r['score'],r['first_seen'],r['id'])}
        rows.sort(key=sorters.get(order, sorters['priority']))
        briefing = []
        if active:
            top = active[0]
            briefing.append({'text': f"Review {top['vulnerability']} on {top['asset']} first under the current policy (score {top['score']:.1f}).", 'fid': top['id']})
            briefing.append({'text': f"{sum(r['overdue'] for r in active)} actionable findings are overdue; {sum(r['exploited'] and r['exposed'] for r in active)} combine an exploitation flag with internet exposure.", 'fid': None})
            if severity_order[0]['id'] != top['id']:
                briefing.append({'text': f"Severity alone puts {severity_order[0]['vulnerability']} first. Asset context changes that order; verify the assumptions before assigning work.", 'fid': severity_order[0]['id']})
        else:
            briefing.append({'text':'No actionable findings. Import a scan or review exceptions and resolved findings.', 'fid':None})
        return render_template('index.html', rows=rows, q=query, state=state,
                               focus=focus, owner=owner, order=order, latest_scan=latest_scan, recent=recent, briefing=briefing,
                               disagreements=[r for r in active if r['movement']>=2][:3],
                               owners=sorted({r['owner'] for r in all_rows}), exposed=sum(r['exposed'] for r in active),
                               exceptions=sum(r['effective_state']=='exception' for r in all_rows),
                               total=len(all_rows), actionable=sum(r['actionable'] for r in all_rows),
                               overdue=sum(r['overdue'] for r in all_rows),
                               exploited=sum(r['actionable'] and r['exploited'] for r in all_rows))

    @app.route('/import', methods=['GET', 'POST'])
    def upload():
        error = None
        if request.method == 'POST':
            try:
                file = request.files.get('file')
                if not file or not file.filename.lower().endswith('.csv'):
                    raise ValueError('Choose a UTF-8 CSV file.')
                text = file.read().decode('utf-8-sig')
                with closing(connect(app.config['DATABASE'])) as db:
                    added, updated = import_csv(db, text)
                flash(f'Import complete: {added} new findings, {updated} repeat observations.')
                return redirect(url_for('index'))
            except (ValueError, UnicodeError) as exc:
                error = str(exc)
        return render_template('import.html', error=error), 400 if error else 200

    @app.route('/finding/<int:fid>', methods=['GET', 'POST'])
    def detail(fid):
        error = None
        with closing(connect(app.config['DATABASE'])) as db:
            row = next((r for r in findings(db) if r['id'] == fid), None)
            if row is None:
                abort(404)
            if request.method == 'POST':
                try:
                    update_finding(db, fid, request.form.get('state', ''),
                                   request.form.get('note', ''), request.form.get('until', ''))
                    flash('Status and investigation note saved.')
                    return redirect(url_for('detail', fid=fid))
                except ValueError as exc:
                    error = str(exc)
            history = db.execute('SELECT * FROM audit WHERE finding_id=? ORDER BY id DESC', (fid,)).fetchall()
        return render_template('detail.html', row=row, history=history, error=error), 400 if error else 200

    @app.get('/evaluation')
    def compare():
        with closing(connect(app.config['DATABASE'])) as db:
            rows = [r for r in findings(db) if r['actionable']]
        baseline, reports = evaluation(rows)
        return render_template('evaluation.html', baseline=baseline, reports=reports)

    @app.errorhandler(413)
    def too_large(_):
        return 'Upload exceeds the 2 MiB limit.', 413

    return app


if __name__ == '__main__':
    create_app().run(host='127.0.0.1', port=int(os.environ.get('PORT', '5050')), debug=False)
