"""Isolated end-to-end experiment fixture; never depends on public network."""
import pytest


@pytest.fixture(scope='session')
def experiment(tmp_path_factory):
    from phishdetect.dataset import build
    from phishdetect.training import train
    directory = tmp_path_factory.mktemp('experiment')
    data = directory / 'data'
    build(data, limit=100, offline=True)
    model = directory / 'model.joblib'
    report = train(data / 'urls.csv', directory / 'outputs', model, quick=True)
    return directory, model, report
