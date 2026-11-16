"""Bounded, network-free URL parsing and lexical features."""
import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit, SplitResult

import numpy as np
import tldextract
from sklearn.base import BaseEstimator, TransformerMixin

# Use the bundled PSL snapshot, including private suffixes; never update online.
PSL = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)
MAX_LENGTH = 8192
SENSITIVE_WORDS = ['login', 'signin', 'verify', 'update', 'secure', 'account',
                   'banking', 'confirm', 'password', 'wallet', 'suspend', 'unlock', 'billing', 'support']
BRANDS = ['paypal', 'google', 'facebook', 'microsoft', 'apple', 'amazon', 'netflix',
          'bkash', 'nagad', 'instagram', 'whatsapp', 'dutchbangla']
# Hand-written prior, not an empirical claim about every domain in these TLDs.
TLDS = {'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'click', 'work', 'zip', 'icu', 'buzz'}
SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'rebrand.ly'}
FEATURE_NAMES = ['url_length', 'host_length', 'path_length', 'query_length', 'num_dots',
 'num_hyphens_host', 'num_digits', 'digit_ratio', 'num_subdomains', 'has_ip_host',
 'has_at_symbol', 'uses_https', 'num_sensitive_words', 'brand_in_subdomain_or_path',
 'suspicious_tld', 'is_shortener', 'has_punycode', 'num_query_params', 'host_entropy',
 'has_port', 'double_slash_in_path', 'num_special_chars', 'digit_letter_transitions',
 'longest_token_length', 'keyword_density', 'path_entropy', 'brand_in_registered_domain',
 'malformed_url', 'percent_encoding_count']


def parse_url(url: str) -> tuple[SplitResult, str, bool]:
    """Parse strings defensively without DNS, HTTP, or port exceptions."""
    raw = str(url).strip()[:MAX_LENGTH]
    try:
        parsed = urlsplit(raw if '://' in raw else 'http://' + raw)
        host = (parsed.hostname or '').lower().rstrip('.')
        host = host.encode('idna').decode('ascii')
        _ = parsed.port
        malformed = not host or any(c.isspace() for c in raw) or parsed.scheme not in {'http', 'https'}
        return parsed, host, malformed
    except (ValueError, UnicodeError):
        return SplitResult('', '', raw, '', ''), '', True


def registered_domain(url: str) -> str:
    """Group by eTLD+1; IPs and unknown suffix hosts remain whole."""
    _, host, _ = parse_url(url)
    ext = PSL(host)
    return ext.top_domain_under_public_suffix or host or '__malformed__'


def entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in Counter(value).values()) if value else 0.0


def extract_features(url: str) -> dict[str, float]:
    """Retain the original 22 features and add seven lexical signals."""
    raw = str(url).strip()[:MAX_LENGTH]
    p, host, malformed = parse_url(raw)
    ext = PSL(host)
    reg = registered_domain(raw)
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    sub = ext.subdomain if ext.suffix else ''
    tokens = re.findall(r'[a-z0-9]+', raw.lower())
    keyword_count = sum(w in raw.lower() for w in SENSITIVE_WORDS)
    # Exact brand label is a conservative ownership heuristic, not ownership proof.
    own_brand = ext.domain in BRANDS
    values = [len(raw), len(host), len(p.path), len(p.query), host.count('.'),
        host.count('-'), sum(c.isdigit() for c in raw), sum(c.isdigit() for c in raw) / max(1, len(raw)),
        len(sub.split('.')) if sub else 0, int(is_ip), int('@' in raw), int(p.scheme == 'https'),
        keyword_count, int(not own_brand and any(b in (sub + p.path.lower()) for b in BRANDS)),
        int(ext.suffix in TLDS), int(host in SHORTENERS), int('xn--' in host),
        len([x for x in p.query.split('&') if x]), entropy(host),
        int(p.port not in (None, 80, 443)) if not malformed else 0, int('//' in p.path),
        sum(raw.count(c) for c in '?=&%_~#'),
        sum((a.isalpha() and b.isdigit()) or (a.isdigit() and b.isalpha()) for a, b in zip(raw, raw[1:])),
        max(map(len, tokens), default=0), keyword_count / max(1, len(tokens)), entropy(p.path),
        int(not own_brand and any(b in reg for b in BRANDS)), int(malformed), raw.count('%')]
    return dict(zip(FEATURE_NAMES, values))


def red_flags(url: str) -> list[str]:
    """Heuristic observations, separate from learned model contributions."""
    f = extract_features(url)
    rules = {'has_ip_host': 'IP address host', 'has_at_symbol': 'Contains @: inspect the actual host',
        'brand_in_subdomain_or_path': 'Brand outside its apparent registered domain',
        'brand_in_registered_domain': 'Brand embedded in a different registered domain',
        'suspicious_tld': 'TLD matches a hand-written risk prior', 'is_shortener': 'Shortened destination',
        'has_punycode': 'Internationalized hostname: inspect for look-alikes',
        'has_port': 'Nonstandard port', 'malformed_url': 'Malformed or unsupported URL'}
    flags = [text for name, text in rules.items() if f[name]]
    if not f['uses_https']:
        flags.append('HTTPS absent; HTTPS itself is not proof of safety')
    if f['url_length'] > 90:
        flags.append('Long URL')
    if f['num_sensitive_words'] >= 2:
        flags.append('Multiple account or credential keywords')
    return flags


class LexicalTransformer(TransformerMixin, BaseEstimator):
    """Sklearn-compatible string-to-numeric feature transformer."""
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return np.asarray([list(extract_features(normalize_model_url(u)).values()) for u in X], dtype=float)

    def get_feature_names_out(self, input_features=None):
        return np.asarray(FEATURE_NAMES)


def normalize_model_url(url: str) -> str:
    """Remove protocol formatting so corpus serialization cannot predict labels.

    HTTPS is still reported as an observation, but is not a learned threat
    signal. Protocol changes cannot change a model's output in this version.
    """
    return re.sub(r'^https?://', '', str(url).strip(), flags=re.IGNORECASE)


def normalize_model_urls(urls) -> np.ndarray:
    """Pickle-safe batch normalizer for the character-model sklearn pipeline."""
    return np.asarray([normalize_model_url(u) for u in urls])
