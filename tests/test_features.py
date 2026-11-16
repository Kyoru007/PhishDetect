"""Regression cases for dangerous parsing and domain-grouping mistakes."""
import math
import socket
import pytest
from phishdetect.features import FEATURE_NAMES, extract_features, registered_domain, red_flags


@pytest.mark.parametrize('url', ['http://192.0.2.1:8080/login', 'https://[2001:db8::1]:443/',
    'https://example.com:99999', 'https://example.com:abc/', 'https://paypal.com@evil.example/',
    'https://xn--bcher-kva.de/', 'example.com/path', 'http://[broken', '', 'http://',
    'https://example.com/' + 'a' * 20000, 'https://bücher.de/', 'http://a.com\n/', 'https://a.example.com:443/'])
def test_features_never_crash(url):
    result = extract_features(url)
    assert list(result) == FEATURE_NAMES
    assert all(math.isfinite(float(v)) for v in result.values())
    assert isinstance(red_flags(url), list)


def test_domain_groups():
    assert registered_domain('https://a.shop.example.co.uk/login') == 'example.co.uk'
    assert registered_domain('https://b.example.co.uk/') == 'example.co.uk'
    assert registered_domain('http://192.0.2.1/') == '192.0.2.1'
    assert registered_domain('https://alice.github.io/') != registered_domain('https://bob.github.io/')


def test_brand_domains():
    assert not extract_features('https://accounts.paypal.com/login')['brand_in_subdomain_or_path']
    assert extract_features('https://paypal.evil.com/login')['brand_in_subdomain_or_path']
    assert extract_features('https://paypal-support.com/')['brand_in_registered_domain']
    assert extract_features('https://paypal.com.evil.com/')['brand_in_subdomain_or_path']


def test_ip_at_and_ports():
    assert extract_features('https://[2001:db8::1]/')['has_ip_host'] == 1
    assert extract_features('http://999.999.999.999/')['has_ip_host'] == 0
    assert extract_features('http://example.com:8080/')['has_port'] == 1
    assert extract_features('https://good.com@evil.com/')['has_at_symbol'] == 1


def test_extraction_is_network_free(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Network access attempted')
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    extract_features('https://paypal.evil.example/verify')
    registered_domain('https://example.co.uk/')


def test_model_representation_is_scheme_neutral():
    import numpy as np
    from phishdetect.features import LexicalTransformer, normalize_model_urls
    urls = ['http://www.example.org/wiki/Article?a=12',
            'https://www.example.org/wiki/Article?a=12',
            'www.example.org/wiki/Article?a=12']
    values = LexicalTransformer().transform(urls)
    assert np.array_equal(values[0], values[1])
    assert np.array_equal(values[1], values[2])
    assert len(set(normalize_model_urls(urls))) == 1
    # Human observations remain distinct from the scheme-neutral model input.
    assert extract_features(urls[0])['uses_https'] == 0
    assert extract_features(urls[1])['uses_https'] == 1
