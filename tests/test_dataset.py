"""Mock source-file downloads; never request any candidate URL."""
import io
import json
import zipfile
import pandas as pd
import requests
from phishdetect.dataset import build, fetch


def test_cached_source_and_offline_fallback(tmp_path, monkeypatch):
    def unavailable(*args, **kwargs):
        raise requests.ConnectionError('Network disabled for test')
    monkeypatch.setattr(requests, 'get', unavailable)
    (tmp_path / 'sample').write_bytes(b'cached')
    assert fetch('sample', 'https://source.example/feed', tmp_path, False) == b'cached'
    meta = build(tmp_path / 'fallback', limit=40)
    assert meta['mode'] == 'synthetic' and meta['fallback_reason']
    assert pd.read_csv(tmp_path / 'fallback/urls.csv').label.value_counts().nunique() == 1


def test_public_source_ingestion(tmp_path, monkeypatch):
    monkeypatch.delenv('PHISHTANK_API_KEY', raising=False)
    content = io.BytesIO()
    with zipfile.ZipFile(content, 'w') as z:
        z.writestr('top-1m.csv', '\n'.join(f'{i},legitimate{i}.com' for i in range(1, 100)))
    phish = '\n'.join(f'https://malicious{i}.net/login' for i in range(40)).encode()
    seen = []
    def fake_fetch(name, url, cache, refresh):
        seen.append(url)
        return phish if name == 'openphish' else content.getvalue()
    monkeypatch.setattr('phishdetect.dataset.fetch', fake_fetch)
    meta = build(tmp_path, limit=35, expanded=False)
    assert meta['mode'] == 'real_public_feeds'
    assert meta['rows'] == 70
    assert len(seen) == 2


def test_optional_phishtank_and_secret_redaction(tmp_path, monkeypatch):
    import bz2
    monkeypatch.setenv('PHISHTANK_API_KEY', 'test-key-not-for-logs')
    content = io.BytesIO()
    with zipfile.ZipFile(content, 'w') as z:
        z.writestr('top.csv', '\n'.join(f'{i},benign{i}.com' for i in range(1, 100)))
    phish = '\n'.join(f'https://phish{i}.net/login' for i in range(40)).encode()
    optional = bz2.compress(json.dumps([{'url': 'https://extra-phish.net/', 'verified': 'yes', 'online': 'yes'}]).encode())
    blobs = {'openphish': phish, 'tranco': content.getvalue(), 'phishtank': optional}
    monkeypatch.setattr('phishdetect.dataset.fetch', lambda name, url, cache, refresh: blobs[name])
    meta = build(tmp_path, limit=60, expanded=False)
    assert 'phishtank' in meta['source_sha256']
    assert 'test-key-not-for-logs' not in json.dumps(meta)
    assert 'https://extra-phish.net/' in pd.read_csv(tmp_path / 'urls.csv').url.values


def test_expanded_benign_data_and_exclusion(tmp_path, monkeypatch):
    monkeypatch.delenv('PHISHTANK_API_KEY', raising=False)
    content = io.BytesIO()
    with zipfile.ZipFile(content, 'w') as z:
        z.writestr('top.csv', '\n'.join(f'{i},root{i}.com' for i in range(1, 100)))
    corpus = pd.DataFrame({'url': [f'archive{i}.org/article?id={i}' for i in range(400)] +
                          ['a.excluded.com/wiki/Article', 'bad-label.net/login'],
                          'label': ['good'] * 401 + ['bad']}).to_csv(index=False).encode()
    blobs = {'openphish': '\n'.join(f'https://phish{i}.net/login' for i in range(40)).encode(),
             'tranco': content.getvalue(), 'legacy_urls': corpus}
    monkeypatch.setattr('phishdetect.dataset.fetch', lambda name, url, cache, refresh: blobs[name])
    meta = build(tmp_path, limit=35, expanded=True, exclude_domains={'excluded.com'})
    assert meta['mode'] == 'public_feeds_with_historical_benign'
    assert meta['class_counts'] == {'0': 175, '1': 35}
    assert meta['url_shape_summary']['0']['query_strings'] == 140
    frame = pd.read_csv(tmp_path / 'urls.csv')
    assert 'excluded.com' not in frame.domain.values
    assert 'bad-label.net/login' not in frame.url.values


def test_historical_domain_cap():
    from phishdetect.dataset import historical_benign
    corpus = pd.DataFrame({'url': [f'prolific.org/article/{i}' for i in range(20)] + ['other.org/phish'],
                           'label': ['good'] * 20 + ['bad']})
    result = historical_benign(corpus.to_csv(index=False).encode())
    assert len(result) == 5
    assert result.label.eq(0).all()
