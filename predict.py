"""CLI using the API model, threshold, and explanations."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent / 'src'))
from phishdetect.inference import Detector


def main() -> None:
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('urls', nargs='*')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    try:
        detector = Detector()
    except FileNotFoundError:
        parser.exit(1, 'Model missing. Run python tasks.py train first.\n')
    urls = args.urls
    if not urls:
        print('Enter URL text (blank line to finish):')
        urls = iter(lambda: input('> ').strip(), '')
    for url in urls:
        try:
            result = detector.predict(url)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f'{result["verdict"]}: {result["probability"]:.1%} (threshold {result["threshold"]:.1%})')
                print(f'Data: {result["dataset_mode"]} | Model: {result["model"]}')
                for flag in result['red_flags']:
                    print(' - ' + flag)
                print(result['notice'])
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            if args.urls:
                sys.exit(2)


if __name__ == '__main__':
    main()
