"""Capture real API-connected UI; requires a running local server."""
import argparse
import json
from pathlib import Path
from playwright.sync_api import sync_playwright
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))


def main() -> None:
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--url', default='http://127.0.0.1:8000')
    parser.add_argument('--channel', default=None)
    parser.add_argument('--executable-path', default=None, help='Use an already installed Chromium browser')
    parser.add_argument('--in-process', action='store_true', help='Route browser HTTP requests to the real ASGI app via TestClient; no TCP listener needed')
    args = parser.parse_args()
    Path('outputs').mkdir(exist_ok=True)
    evidence = {'transport': 'FastAPI TestClient' if args.in_process else 'HTTP TCP', 'screens': []}
    client = None
    if args.in_process:
        from fastapi.testclient import TestClient
        from phishdetect.api import create_app
        client = TestClient(create_app())
        client.__enter__()
    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel=args.channel, executable_path=args.executable_path)
        evidence['browser_version'] = browser.version
        for name, width, height, theme in [('desktop', 1440, 1300, 'dark'), ('mobile', 390, 844, 'light')]:
            page = browser.new_page(viewport={'width': width, 'height': height}, color_scheme=theme)
            errors = []
            page.on('pageerror', lambda exc: errors.append(str(exc)))
            if client:
                def handle(route):
                    from urllib.parse import urlsplit
                    request = route.request
                    parts = urlsplit(request.url)
                    path = parts.path + ('?' + parts.query if parts.query else '')
                    response = client.request(request.method, path, content=request.post_data_buffer, headers={'content-type': request.headers.get('content-type', '')})
                    route.fulfill(status=response.status_code, headers={'content-type': response.headers.get('content-type', '')}, body=response.content)
                page.route('**/*', handle)
            page.goto('http://phishdetect.test/' if client else args.url)
            page.get_by_role('button', name='Brand lure', exact=True).click()
            page.locator('#result').wait_for(state='visible')
            page.wait_for_timeout(500)
            assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), 'Horizontal overflow'
            assert not errors, errors
            page.screenshot(path=f'outputs/ui-{name}.png', full_page=True)
            evidence['screens'].append({'name': name, 'width': width, 'theme': theme,
                'verdict': page.locator('#verdict').inner_text(), 'rendered_score': page.locator('#score').inner_text(),
                'console_errors': errors, 'horizontal_overflow': False})
            page.close()
        browser.close()
    if client:
        client.__exit__(None, None, None)
    metrics = Path('outputs/metrics.json')
    if metrics.exists():
        evidence['dataset_sha256'] = json.loads(metrics.read_text(encoding='utf-8'))['dataset_sha256']
    Path('outputs/screenshots.json').write_text(json.dumps(evidence, indent=2), encoding='utf-8')
    print('Captured API-connected desktop/mobile results; no JS errors or horizontal overflow.')


if __name__ == '__main__':
    main()
