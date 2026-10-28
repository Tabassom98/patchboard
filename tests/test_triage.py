import unittest
from datetime import date
from pathlib import Path

from triage import (FIELDS, connect, evaluation, findings, import_csv, parse_csv,
                    score, update_finding)

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = (ROOT / 'data/scan-01.csv').read_text()


class TriageTests(unittest.TestCase):
    def setUp(self):
        self.db = connect(':memory:')
        self.addCleanup(self.db.close)

    def test_scores_have_explainable_bounds(self):
        for severity, criticality, exposed, exploited, expected in [(0, 1, 0, 0, 0), (10, 5, 1, 1, 116)]:
            value, parts = score(dict(severity=severity, criticality=criticality,
                                     exposed=exposed, exploited=exploited))
            self.assertEqual(value, expected)
            self.assertEqual(sum(parts.values()), expected)

    def test_invalid_row_rejects_entire_batch(self):
        bad = SAMPLE.replace('8.1,yes', 'NaN,yes')
        with self.assertRaisesRegex(ValueError, 'Row 2'):
            import_csv(self.db, bad)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM findings').fetchone()[0], 0)

    def test_duplicate_and_conflicting_asset_rejected(self):
        lines = SAMPLE.splitlines()
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            parse_csv(SAMPLE + '\n' + lines[1])
        changed = lines[1].replace('Web services', 'Other owner').replace('LAB-001', 'LAB-999')
        with self.assertRaisesRegex(ValueError, 'conflicting'):
            parse_csv(SAMPLE + '\n' + changed)

    def test_infinite_and_out_of_range_values(self):
        for value in ['inf', '-inf', '10.1', '-0.1']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_csv(SAMPLE.replace('8.1,yes', value + ',yes'))

    def test_reimport_retains_identity_and_first_seen(self):
        self.assertEqual(import_csv(self.db, SAMPLE), (10, 0))
        ids = [(r['id'], r['first_seen']) for r in findings(self.db)]
        self.assertEqual(import_csv(self.db, SAMPLE), (0, 10))
        self.assertEqual(ids, [(r['id'], r['first_seen']) for r in findings(self.db)])

    def test_repeat_observation_reopens_resolved_and_does_not_resolve_absent(self):
        import_csv(self.db, SAMPLE)
        target = next(r for r in findings(self.db) if r['vulnerability'] == 'LAB-001')
        update_finding(self.db, target['id'], 'resolved', 'Patch installed in lab')
        import_csv(self.db, (ROOT / 'data/scan-02.csv').read_text())
        rows = {r['vulnerability']: r for r in findings(self.db)}
        self.assertEqual(rows['LAB-001']['state'], 'open')
        self.assertEqual(rows['LAB-001']['first_seen'], '2026-10-01')
        self.assertEqual(rows['LAB-001']['last_seen'], '2026-10-15')
        self.assertEqual(rows['LAB-003']['state'], 'open')
        self.assertEqual(len(rows), 11)

    def test_older_scan_rolls_back_all_updates(self):
        import_csv(self.db, SAMPLE)
        # First row would succeed; second is stale. Neither observation should commit.
        lines = SAMPLE.splitlines()
        batch = '\n'.join([lines[0], lines[1].replace('2026-10-01', '2026-10-15'),
                           lines[2].replace('2026-10-01', '2026-09-01')])
        before = self.db.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
        with self.assertRaisesRegex(ValueError, 'Older scan'):
            import_csv(self.db, batch)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM audit').fetchone()[0], before)
        self.assertTrue(all(r['last_seen'] == '2026-10-01' for r in findings(self.db)))

    def test_exception_boundary_and_expiry(self):
        import_csv(self.db, SAMPLE)
        fid = findings(self.db)[0]['id']
        today = date(2026, 10, 20)
        update_finding(self.db, fid, 'exception', 'Maintenance scheduled', '2026-10-20', today)
        current = next(r for r in findings(self.db, today) if r['id'] == fid)
        self.assertFalse(current['actionable'])
        expired = next(r for r in findings(self.db, date(2026, 10, 21)) if r['id'] == fid)
        self.assertEqual(expired['effective_state'], 'exception_expired')
        self.assertTrue(expired['overdue'])
        with self.assertRaises(ValueError):
            update_finding(self.db, fid, 'exception', 'Too long', '2027-10-20', today)

    def test_no_blank_decisions_or_unknown_states(self):
        import_csv(self.db, SAMPLE)
        for state, note in [('resolved', ' '), ('deleted', 'test')]:
            with self.assertRaises(ValueError):
                update_finding(self.db, 1, state, note)

    def test_known_scenario_rank_reversal_and_sensitivity(self):
        import_csv(self.db, SAMPLE)
        baseline, reports = evaluation(findings(self.db))
        self.assertEqual(baseline[0]['vulnerability'], 'LAB-003')
        self.assertEqual(reports[0]['ranked'][0][0]['vulnerability'], 'LAB-001')
        # LAB-002, LAB-005 and LAB-006 occur in both top-five sets.
        self.assertEqual(reports[0]['overlap'], 3 / 5)
        for report in reports:
            self.assertEqual(len(report['ranked']), 10)
            self.assertEqual({r['id'] for r, _, _ in report['ranked']}, set(range(1, 11)))


if __name__ == '__main__':
    unittest.main()
