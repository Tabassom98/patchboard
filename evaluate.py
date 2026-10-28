"""Reproduce the sample ranking comparison without installing Flask."""
from pathlib import Path
from triage import connect, evaluation, findings, import_csv


def main():
    with connect(':memory:') as db:
        import_csv(db, Path(__file__).with_name('data').joinpath('scan-01.csv').read_text())
        baseline, reports = evaluation(findings(db))
        print('Severity-only:', ', '.join(r['vulnerability'] for r in baseline[:5]))
        for report in reports:
            print(f"\n{report['name']}: top-five overlap {report['overlap']:.0%}")
            for rank, (r, value, movement) in enumerate(report['ranked'], 1):
                print(f"{rank:2} {r['vulnerability']} {r['asset']:20} score={value:6.2f} movement={movement:+d}")
        print('\nSynthetic scenario; ranking changes are not evidence of predictive accuracy.')


if __name__ == '__main__':
    main()
