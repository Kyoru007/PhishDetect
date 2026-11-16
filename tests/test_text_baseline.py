"""Exercise the text model's explanation path even when a lexical model wins CV."""
import json
import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.frozen import FrozenEstimator
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from phishdetect.features import LexicalTransformer
from phishdetect.inference import Detector
from phishdetect.training import draw_charts


def test_text_inference_and_permutation(tmp_path):
    urls = np.asarray([f'https://site{i}.com/' for i in range(12)] + [f'http://account{i}.net/login/verify' for i in range(12)])
    y = np.asarray([0] * 12 + [1] * 12)
    fit = np.r_[0:8, 12:20]
    calibration = np.r_[8:12, 20:24]
    estimator = make_pipeline(TfidfVectorizer(analyzer='char', ngram_range=(3, 4)), LogisticRegression())
    estimator.fit(urls[fit], y[fit])
    model = CalibratedClassifierCV(FrozenEstimator(estimator), method='sigmoid', cv=2).fit(urls[calibration], y[calibration])
    bundle = {'model': model, 'kind': 'text', 'name': 'Text test model', 'threshold': .5, 'dataset_mode': 'synthetic'}
    path = tmp_path / 'model.joblib'
    joblib.dump(bundle, path)
    result = Detector(path).predict('http://account19.net/login/verify')
    assert result['contributions']
    assert all(item['value'] is None for item in result['contributions'])
    probs = model.predict_proba(urls[calibration])[:, 1]
    draw_charts(y[calibration], probs, probs >= .5, bundle,
                LexicalTransformer().transform(urls[calibration]), urls[calibration], tmp_path)
    summary = json.loads((tmp_path / 'global_importance.json').read_text())
    assert summary['method'].startswith('URL-component permutation')
    assert len(summary['features']) == 5
