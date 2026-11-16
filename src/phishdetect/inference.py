"""Shared API/CLI inference with honest local feature perturbations."""
import re
from pathlib import Path
import joblib
import numpy as np
from .features import FEATURE_NAMES, MAX_LENGTH, LexicalTransformer, extract_features, parse_url, red_flags, normalize_model_url


class Detector:
    """Load only a trusted local model artifact; never fetch submitted URLs."""
    def __init__(self, path: Path = Path('models/phish_model.joblib')) -> None:
        self.bundle = joblib.load(path)

    def predict(self, url: str) -> dict:
        """Return the calibrated score and one-at-a-time baseline perturbations."""
        if not url.strip() or len(url) > MAX_LENGTH or parse_url(url)[2]:
            raise ValueError(f'Enter a valid HTTP(S) URL of at most {MAX_LENGTH} characters')
        bundle = self.bundle
        values = (LexicalTransformer().transform([url]) if bundle.get('representation') == 'scheme_neutral_v1'
                  else np.asarray([list(extract_features(url).values())], dtype=float))
        model = bundle['model']
        inputs = values if bundle['kind'] == 'lexical' else [url]
        probability = float(model.predict_proba(inputs)[0, 1])
        if bundle['kind'] == 'lexical':
            changed = np.repeat(values, len(FEATURE_NAMES), axis=0)
            np.fill_diagonal(changed, bundle['reference'])
            deltas = probability - model.predict_proba(changed)[:, 1]
            contributions = [{'feature': name, 'value': float(values[0, i]), 'contribution': float(deltas[i])} for i, name in enumerate(FEATURE_NAMES)]
        else:
            tokens = list(dict.fromkeys(re.findall(r'[a-zA-Z0-9-]{3,}', normalize_model_url(url))))[:40]
            scores = model.predict_proba([url.replace(t, '') for t in tokens])[:, 1] if tokens else []
            contributions = [{'feature': t, 'value': None, 'contribution': probability - float(p)} for t, p in zip(tokens, scores)]
        return {'probability': probability, 'verdict': 'PHISHING RISK' if probability >= bundle['threshold'] else 'LOWER MODEL RISK',
            'threshold': bundle['threshold'], 'red_flags': red_flags(url),
            'contributions': sorted(contributions, key=lambda c: abs(c['contribution']), reverse=True)[:8],
            'explanation_method': 'One-at-a-time probability change versus training median (lexical) or removed token (text); non-additive, not causal or SHAP',
            'model': bundle['name'], 'dataset_mode': bundle['dataset_mode'],
            'dataset_sha256': bundle.get('dataset_sha256'),
            'notice': 'Unverified model score, not a measured probability that this page is phishing. Historical labels and source bias limit reliability.'}
