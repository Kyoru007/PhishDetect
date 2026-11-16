"""Actual small-sample training, split leakage, artifact and inference checks."""
import pandas as pd
from phishdetect.inference import Detector


def test_training_and_partitions(experiment):
    directory, model, report = experiment
    assert model.exists()
    assert report['dataset']['mode'] == 'synthetic'
    assignments = pd.read_csv(directory / 'outputs/split_assignments.csv')
    assert assignments.groupby('domain').partition.nunique().max() == 1
    assert set(assignments.partition) == {'fit', 'calibration', 'threshold', 'test'}
    assert report['domain_overlap'] == 0
    assert len(report['models']) >= 4
    for result in report['models'].values():
        assert 0 <= result['test']['roc_auc'] <= 1
        assert result['threshold_set']['recall'] >= .9
    detector = Detector(model)
    result = detector.predict('http://paypal.login-check.example/verify')
    assert 0 <= result['probability'] <= 1
    assert result['contributions']
    assert result['threshold'] == report['models'][report['best_model']]['test']['threshold']
    scores = [detector.predict(url)['probability'] for url in
              ['https://example.com/article?id=123', 'http://example.com/article?id=123', 'example.com/article?id=123']]
    assert max(scores) - min(scores) < 1e-12
    errors = pd.read_csv(directory / 'outputs/errors.csv')
    assert (errors.label != errors.prediction).all()
