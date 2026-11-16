"""Independent user-reported false-positive diagnostics; never training rows."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import pandas as pd
from phishdetect.features import registered_domain
from phishdetect.inference import Detector

EXAMPLES = [
    'https://awoiaf.westeros.org/index.php/Game_of_Thrones',
    'https://www.youtube.com/watch?v=MKTT4J-aby8&list=RDMKTT4J-aby8&start_radio=1',
]


def main() -> None:
    domains = set(pd.read_csv('data/urls.csv').url.map(registered_domain))
    assert not domains & {registered_domain(url) for url in EXAMPLES}, 'Diagnostic domains leaked into the dataset'
    detector = Detector()
    checks = []
    for url in EXAMPLES:
        prediction = detector.predict(url)
        checks.append({'url': url, 'score': prediction['probability'], 'threshold': prediction['threshold'],
                       'flagged': prediction['probability'] >= prediction['threshold'],
                       'domain_absent_from_dataset': True})
    report = {'dataset_sha256': detector.bundle['dataset_sha256'], 'checks': checks,
              'notice': 'User-reported benign examples; not independently page-verified. These diagnostics influenced development, so are not unbiased evaluation.'}
    Path('outputs/regression_examples.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))
    if any(check['flagged'] for check in checks):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
