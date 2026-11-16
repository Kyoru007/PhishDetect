"""HTTP contract, error handling, inert rendering and offline inference."""
import socket
from fastapi.testclient import TestClient
from phishdetect.api import create_app


def test_api(experiment, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Prediction attempted DNS')
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    with TestClient(create_app(experiment[1])) as client:
        assert client.get('/health').json()['model_loaded']
        assert client.get('/').status_code == 200
        assert client.get('/static/app.js').status_code == 200
        result = client.post('/predict', json={'url': 'example.com/path'})
        assert result.status_code == 200
        data = result.json()
        assert data['dataset_mode'] == 'synthetic'
        assert data['contributions'] and data['red_flags']
        assert 0 <= data['probability'] <= 1
        for url in ['', 'http://[bad', 'https://a.com:wrong', 'x' * 8193]:
            assert client.post('/predict', json={'url': url}).status_code == 422


def test_missing_model(tmp_path):
    with TestClient(create_app(tmp_path / 'absent.joblib')) as client:
        assert client.get('/health').json()['status'] == 'model_missing'
        assert client.post('/predict', json={'url': 'https://example.com/'}).status_code == 503
