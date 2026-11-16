"""Cached public source ingestion with explicit synthetic fallback provenance."""
import argparse
import bz2
import hashlib
import io
import json
import os
from pathlib import Path
import random
import warnings
import zipfile
from datetime import datetime, timezone

import pandas as pd
import requests

from .features import parse_url, registered_domain

SOURCES = {'openphish': 'https://openphish.com/feed.txt',
           'tranco': 'https://tranco-list.eu/top-1m.csv.zip'}
BENIGN_CORPUS = 'https://raw.githubusercontent.com/faizann24/Using-machine-learning-to-detect-malicious-URLs/master/data/data.csv'


def historical_benign(blob: bytes, max_pool: int = 50000) -> pd.DataFrame:
    """Use only historical 'good' labels; 'bad' is not a phishing label.

    Strings are not live-verified. Sample before domain capping to avoid a
    handful of prolific websites dominating the legitimate class.
    """
    frame = pd.read_csv(io.BytesIO(blob), usecols=['url', 'label'])
    frame = frame.loc[frame.label == 'good', ['url']].dropna().drop_duplicates('url')
    frame = frame.sample(min(max_pool, len(frame)), random_state=42)
    frame['domain'] = frame.url.map(registered_domain)
    frame = frame.groupby('domain', sort=False).head(5).copy()
    frame['label'], frame['source'] = 0, 'historical_good_labels'
    return frame


def fetch(name: str, url: str, cache: Path, refresh: bool) -> bytes:
    """Fetch only explicitly configured provider endpoints; reuse cached bytes."""
    path = cache / name
    if not refresh and path.exists():
        return path.read_bytes()
    response = requests.get(url, timeout=(10, 45), headers={'User-Agent': 'phishdetect-research/0.2'}, allow_redirects=True)
    response.raise_for_status()
    path.write_bytes(response.content)
    return response.content


def synthetic(n: int = 600) -> pd.DataFrame:
    """Use the preserved original generator; isolate its random state."""
    from . import synthetic as generate_data
    random.seed(42)
    rows = [(generate_data.legit(), 0, 'synthetic'), (generate_data.phishing(), 1, 'synthetic')]
    for _ in range(n - 1):
        rows.extend([(generate_data.legit(), 0, 'synthetic'), (generate_data.phishing(), 1, 'synthetic')])
    return pd.DataFrame(rows, columns=['url', 'label', 'source'])


def build(output: Path, limit: int = 3000, offline: bool = False, refresh: bool = False,
          expanded: bool = True, exclude_domains: set[str] | None = None) -> dict:
    """Balance unique URL classes; remove exact conflicts and record hashes."""
    output.mkdir(parents=True, exist_ok=True)
    cache = output / 'cache'
    cache.mkdir(exist_ok=True)
    hashes, reason = {}, None
    endpoints = dict(SOURCES)
    excluded = set(exclude_domains or ())
    try:
        if offline:
            raise RuntimeError('Synthetic mode explicitly requested')
        blobs = {name: fetch(name, url, cache, refresh) for name, url in SOURCES.items()}
        hashes = {k: hashlib.sha256(v).hexdigest() for k, v in blobs.items()}
        phish = [u.strip() for u in blobs['openphish'].decode().splitlines() if u.startswith(('http://', 'https://'))]
        key = os.getenv('PHISHTANK_API_KEY')
        if key:
            try:
                blob = fetch('phishtank', f'https://data.phishtank.com/data/{key}/online-valid.json.bz2', cache, refresh)
                phish.extend(x['url'] for x in json.loads(bz2.decompress(blob)) if x.get('verified') == 'yes' and x.get('online') == 'yes')
                hashes['phishtank'] = hashlib.sha256(blob).hexdigest()
            except (requests.RequestException, ValueError, OSError, KeyError):
                warnings.warn('Optional PhishTank unavailable; continuing with OpenPhish (key omitted).')
        with zipfile.ZipFile(io.BytesIO(blobs['tranco'])) as archive:
            domains = pd.read_csv(archive.open(archive.namelist()[0]), header=None, names=['rank', 'domain'])
        legit = ['https://' + d + '/' for d in domains.domain.astype(str).head(max(limit * 10, 10000))]
        df = pd.DataFrame([(u, 1, 'openphish_or_phishtank') for u in phish] + [(u, 0, 'tranco') for u in legit], columns=['url', 'label', 'source'])
        if len(phish) < 30:
            raise ValueError('Feed contains fewer than 30 phishing URLs')
        mode = 'real_public_feeds'
        if expanded:
            blob = fetch('legacy_urls', BENIGN_CORPUS, cache, refresh)
            hashes['historical_benign'] = hashlib.sha256(blob).hexdigest()
            endpoints['historical_benign'] = BENIGN_CORPUS
            df = pd.concat([df, historical_benign(blob)], ignore_index=True)
            mode = 'public_feeds_with_historical_benign'
    except (requests.RequestException, ValueError, OSError, RuntimeError, zipfile.BadZipFile) as exc:
        reason = str(exc).split('?')[0] if not os.getenv('PHISHTANK_API_KEY') else 'Required feed unavailable'
        warnings.warn(f'SYNTHETIC FALLBACK: {reason}. Scores are NOT real-world accuracy.')
        df, mode = synthetic(min(limit, 1500)), 'synthetic'
    df = df[(df.url.str.len() <= 8192) & ~df.url.map(lambda u: parse_url(u)[2])]
    conflicts = df.groupby('url').label.nunique()
    df = df[~df.url.isin(conflicts[conflicts > 1].index)].drop_duplicates('url')
    # Exclude ranked sites sharing a phishing domain: contradictory weak labels.
    df['domain'] = df.url.map(registered_domain)
    df = df[~df.domain.isin(excluded)]
    bad_domains = set(df.loc[df.label == 1, 'domain'])
    df = df[~((df.label == 0) & df.domain.isin(bad_domains))]
    count = min(limit, int(df.groupby('label').size().min()))
    if mode == 'public_feeds_with_historical_benign':
        positives = df[df.label == 1].sample(count, random_state=42)
        roots = df[df.source == 'tranco']
        history = df[df.source == 'historical_good_labels']
        if len(history) < count * 4:
            raise ValueError('Expanded mode needs at least four historical benign URLs per phishing URL')
        # 80% deep/varied historical strings, 20% root URLs. No artificial paths.
        negatives = pd.concat([roots.sample(min(count, len(roots)), random_state=42),
                               history.sample(count * 4, random_state=42)])
        df = pd.concat([positives, negatives]).sample(frac=1, random_state=42)
    else:
        df = pd.concat([part.sample(count, random_state=42) for _, part in df.groupby('label')]).sample(frac=1, random_state=42)
    df.to_csv(output / 'urls.csv', index=False)
    shapes = {}
    for label, part in df.groupby('label'):
        parsed = part.url.map(lambda u: parse_url(u)[0])
        shapes[str(label)] = {'rows': len(part), 'deep_paths': int(parsed.map(lambda p: len(p.path) > 1).sum()),
                              'query_strings': int(parsed.map(lambda p: bool(p.query)).sum())}
    meta = {'mode': mode, 'rows': len(df), 'per_class': count if mode != 'public_feeds_with_historical_benign' else None,
        'class_counts': {str(k): int(v) for k, v in df.label.value_counts().items()},
        'source_counts': {str(k): int(v) for k, v in df.source.value_counts().items()},
        'url_shape_summary': shapes,
        'excluded_diagnostic_domains': sorted(excluded), 'built_at_utc': datetime.now(timezone.utc).isoformat(),
        'source_endpoints': endpoints, 'source_sha256': hashes, 'fallback_reason': reason,
        'source_cache_modified_utc': {p.name: datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).isoformat() for p in cache.iterdir() if p.is_file()},
        'dataset_sha256': hashlib.sha256((output / 'urls.csv').read_bytes()).hexdigest(),
        'label_caveat': 'Tranco roots are weak negatives. Historical good labels are inherited, old and not live-verified; no candidate URL is fetched.'}
    (output / 'provenance.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
    print(json.dumps(meta, indent=2))
    return meta


def main() -> None:
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--synthetic', action='store_true')
    parser.add_argument('--refresh', action='store_true')
    parser.add_argument('--limit', type=int, default=3000)
    parser.add_argument('--roots-only', action='store_true', help='Reproduce the limited original roots-only baseline')
    parser.add_argument('--exclude-domain', action='append', default=[], help='Keep an entire registered domain outside all experiment partitions')
    args = parser.parse_args()
    build(Path('data'), args.limit, args.synthetic, args.refresh, not args.roots_only, set(args.exclude_domain))
