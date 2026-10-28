"""Integration checks. Require Flask; explicitly skipped when unavailable."""
import tempfile
import unittest
from pathlib import Path

try:
    from app import create_app
except ModuleNotFoundError as exc:
    if exc.name != 'flask':
        raise
    create_app = None


@unittest.skipIf(create_app is None, 'Flask is not installed')
class WebTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = create_app(str(Path(self.temp.name) / 'test.db'))
        self.app.config.update(TESTING=True)
        self.client = self.app.test_client()

    def test_empty_pages_and_missing_finding(self):
        for url in ['/', '/import', '/evaluation']:
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            self.assertIn('Content-Security-Policy', response.headers)
        self.assertEqual(self.client.get('/finding/999').status_code, 404)

    def test_write_requires_csrf(self):
        self.assertEqual(self.client.post('/import').status_code, 400)
        self.assertEqual(self.client.post('/import', data={'csrf': 'invalid-☃'}).status_code, 400)

    def test_import_detail_and_workflow(self):
        import io
        self.client.get('/')
        with self.client.session_transaction() as session:
            token = session['csrf']
        sample = Path(__file__).resolve().parents[1] / 'data/scan-01.csv'
        response = self.client.post('/import', data={'csrf': token,
            'file': (io.BytesIO(sample.read_bytes()), 'scan.csv')}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'student-portal', response.data)
        detail = self.client.get('/finding/1')
        self.assertIn(b'+48.60', detail.data)
        self.assertNotIn(b'48.599999999', detail.data)
        response = self.client.post('/finding/1', data={'csrf': token,
            'state': 'in_progress', 'note': '<script>alert(1)</script>'}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'&lt;script&gt;', response.data)
        self.assertNotIn(b'<script>alert(1)</script>', response.data)
        self.assertEqual(self.client.get('/evaluation').status_code, 200)

    def test_workbench_filters_sorting_and_local_briefing(self):
        from triage import connect, import_csv
        from contextlib import closing
        sample = Path(__file__).resolve().parents[1] / 'data/scan-01.csv'
        with closing(connect(self.app.config['DATABASE'])) as db:
            import_csv(db, sample.read_text())
        page = self.client.get('/')
        self.assertIn(b'No AI model connected', page.data)
        self.assertIn(b'LAB-001 on student-portal first', page.data)
        self.assertIn(b'2 actionable findings are overdue', page.data)
        self.assertIn(b'Latest import', page.data)
        # Isolate queue rows from briefing and decision context elsewhere on the page.
        def table(url):
            html = self.client.get(url).data.decode()
            return html.split('<tbody>')[1].split('</tbody>')[0]
        overdue = table('/?focus=overdue')
        self.assertIn('LAB-001', overdue)
        self.assertIn('LAB-004', overdue)
        self.assertNotIn('LAB-003', overdue)
        team = table('/?owner=Research+support')
        self.assertIn('LAB-003', team)
        self.assertNotIn('LAB-001', team)
        severity = table('/?sort=severity')
        self.assertLess(severity.index('LAB-003'), severity.index('LAB-001'))
        self.assertIn('No findings match', table('/?q=not-an-asset'))

    def test_briefing_tracks_state_and_escapes_notes(self):
        from triage import connect, import_csv, update_finding
        from contextlib import closing
        sample = Path(__file__).resolve().parents[1] / 'data/scan-01.csv'
        with closing(connect(self.app.config['DATABASE'])) as db:
            import_csv(db, sample.read_text())
            update_finding(db, 1, 'resolved', '<img src=x onerror=alert(1)>')
        html = self.client.get('/').data
        self.assertIn(b'LAB-004 on vpn-gateway first', html)
        self.assertIn(b'&lt;img', html)
        self.assertNotIn(b'<img src=x', html)

    def test_public_export_has_no_mutation_forms_or_private_database(self):
        from scripts.build_demo import build
        output = build(Path(self.temp.name) / 'public-demo')
        self.assertEqual(len(list(output.glob('finding-*.html'))), 11)
        for page in output.glob('*.html'):
            html = page.read_text(encoding='utf-8')
            self.assertNotIn('name="csrf"', html)
            self.assertNotIn('method="post"', html)
            self.assertNotIn('Browser QA', html)
            self.assertNotIn('href="/finding/', html)
        self.assertFalse(list(output.glob('*.db')))
