"""Export a read-only synthetic portfolio demo. Never reads patchboard.db."""
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app import create_app
from triage import connect, import_csv


def build(destination):
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as scratch:
        database = str(Path(scratch) / 'demo.db')
        app = create_app(database)
        db = connect(database)
        try:
            for name in ['scan-01.csv', 'scan-02.csv']:
                import_csv(db, (ROOT / 'data' / name).read_text())
        finally:
            db.close()
        client = app.test_client()
        routes = {'/': 'index.html', '/evaluation': 'evaluation.html', '/import': 'import.html'}
        routes.update({f'/finding/{i}': f'finding-{i}.html' for i in range(1, 12)})
        for route, filename in routes.items():
            response = client.get(route)
            if response.status_code != 200:
                raise RuntimeError(f'{route}: {response.status_code}')
            html = response.data.decode()
            # Remove all mutation forms and session tokens from the public export.
            if route != '/':
                html = re.sub(r'<form\b.*?</form>', '<p class="notice">Read-only demo. Run the Python app locally to import scans or record decisions.</p>', html, flags=re.S)
            html = html.replace('name="csrf"', 'name="removed-csrf"')
            html = html.replace('SYNTHETIC DATA', 'PUBLIC DEMO')
            html = html.replace('● Local workspace', 'Synthetic-data preview')
            html = html.replace('Single operator · No live scanner connection', 'Read-only sample · No uploads or shared database')
            banner = '<p class="notice">Portfolio demo · Synthetic findings only. <a href="https://github.com/Tabassom98/patchboard">View the Python source and run the full app →</a></p>'
            html = html.replace('<main id="main">', '<main id="main">' + banner)
            html = html.replace('href="/static/style.css"', 'href="style.css"')
            # Translate known local routes without changing external links.
            for path, target in sorted(routes.items(), key=lambda p: -len(p[0])):
                html = html.replace(f'href="{path}"', f'href="{target}"')
                html = html.replace(f'href="{path}?', f'href="{target}?')
            html = html.replace('action="/"', 'action="index.html"')
            if route == '/':
                html = html.replace('</body>', '<script src="demo.js"></script></body>')
            if route.startswith('/finding/'):
                html = re.sub(r'(<h2>Record a decision</h2>).*?(</section></div>)', r'\1<p>This hosted sample is read-only. The local Python app supports investigation notes, remediation states, and expiring exceptions.</p>\2', html, flags=re.S)
            (destination / filename).write_text(html, encoding='utf-8')
    shutil.copyfile(ROOT / 'static/style.css', destination / 'style.css')
    shutil.copyfile(ROOT / 'scripts/demo.js', destination / 'demo.js')
    for name in ['scan-01.csv', 'scan-02.csv']:
        shutil.copyfile(ROOT / 'data' / name, destination / name)
    (destination / '.nojekyll').write_text('')
    return destination


if __name__ == '__main__':
    print(build(Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / 'demo'))
