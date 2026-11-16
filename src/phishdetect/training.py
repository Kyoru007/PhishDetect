"""Grouped selection, independent calibration/threshold sets, held-out evaluation."""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.frozen import FrozenEstimator
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, confusion_matrix, precision_recall_curve,
    precision_score, recall_score, f1_score, roc_auc_score, roc_curve, brier_score_loss)
from sklearn.model_selection import GroupShuffleSplit, StratifiedGroupKFold, GridSearchCV
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler, FunctionTransformer

from .features import FEATURE_NAMES, LexicalTransformer, registered_domain, normalize_model_urls


def grouped_partition(y: np.ndarray, groups: np.ndarray, fraction: float, seed: int) -> tuple:
    """Deterministically retry group splits until both partitions contain both labels."""
    for train, test in GroupShuffleSplit(n_splits=100, test_size=fraction, random_state=seed).split(y, y, groups):
        if len(set(y[train])) == 2 and len(set(y[test])) == 2:
            return train, test
    raise ValueError('Too few independent domains to make a two-class grouped split')


def threshold_for(y: np.ndarray, scores: np.ndarray, target: float = .90) -> float:
    """Maximize precision subject to target recall on the threshold set only."""
    precision, recall, thresholds = precision_recall_curve(y, scores)
    valid = np.flatnonzero(recall[:-1] >= target)
    # Tie-break toward the highest threshold among equal-precision candidates.
    return float(thresholds[max(valid, key=lambda i: (precision[i], thresholds[i]))])


def metrics_for(y: np.ndarray, scores: np.ndarray, threshold: float) -> dict:
    """Compute classification and ranking metrics without undefined divisions."""
    pred = scores >= threshold
    cm = confusion_matrix(y, pred, labels=[0, 1])
    fpr, tpr, _ = roc_curve(y, scores)
    return {'precision': float(precision_score(y, pred, zero_division=0)),
        'recall': float(recall_score(y, pred)), 'f1': float(f1_score(y, pred)),
        'pr_auc_average_precision': float(average_precision_score(y, scores)),
        'roc_auc': float(roc_auc_score(y, scores)), 'brier_score': float(brier_score_loss(y, scores)),
        'confusion_matrix': cm.tolist(), 'false_positive_rate': float(cm[0, 1] / cm[0].sum()),
        'fpr_at_90pct_recall_descriptive': float(min(fpr[tpr >= .9])), 'threshold': threshold}


def train(data_path: Path = Path('data/urls.csv'), output: Path = Path('outputs'),
          model_path: Path = Path('models/phish_model.joblib'), quick: bool = False) -> dict:
    """Run a reproducible four-part experiment and persist its complete audit trail."""
    output.mkdir(parents=True, exist_ok=True)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    frame = pd.read_csv(data_path)
    if frame.groupby('url').label.nunique().max() > 1:
        raise ValueError('Conflicting labels for the same URL; clean the dataset first')
    frame = frame.drop_duplicates('url')
    if frame.url.isna().any() or not set(frame.label) == {0, 1}:
        raise ValueError('Expected nonempty URL strings and binary labels 0/1')
    groups = frame.url.map(registered_domain).to_numpy()
    urls, y = frame.url.to_numpy(), frame.label.to_numpy()
    dev, test = grouped_partition(y, groups, .2, 42)
    rest, threshold_rel = grouped_partition(y[dev], groups[dev], .2, 43)
    threshold_idx = dev[threshold_rel]
    fit_rel, calibration_rel = grouped_partition(y[dev[rest]], groups[dev[rest]], .2, 44)
    fit, calibration = dev[rest][fit_rel], dev[rest][calibration_rel]
    splits = {'fit': fit, 'calibration': calibration, 'threshold': threshold_idx, 'test': test}
    audit = {name: {'rows': len(idx), 'domains': len(set(groups[idx])),
        'phishing': int(y[idx].sum())} for name, idx in splits.items()}
    for name, idx in splits.items():
        for other, jdx in splits.items():
            if name != other:
                assert not set(groups[idx]) & set(groups[jdx])
    X = LexicalTransformer().fit_transform(urls)
    specs = {
        'Logistic Regression': ('lexical', make_pipeline(StandardScaler(), LogisticRegression(max_iter=1500, random_state=42)), {'logisticregression__C': [.1, 1.0]}),
        'Random Forest': ('lexical', RandomForestClassifier(n_estimators=80 if quick else 180, n_jobs=1, random_state=42), {'min_samples_leaf': [1, 3]}),
        'Gradient Boosting': ('lexical', GradientBoostingClassifier(n_estimators=40 if quick else 100, random_state=42), {'max_depth': [2, 3]}),
        'Character TF-IDF + Logistic': ('text', make_pipeline(FunctionTransformer(normalize_model_urls, validate=False), TfidfVectorizer(analyzer='char', ngram_range=(3, 5), min_df=2, max_features=20000, sublinear_tf=True), LogisticRegression(max_iter=1500, random_state=42)), {'logisticregression__C': [.5, 2.0]}),
    }
    optional = None
    try:
        from xgboost import XGBClassifier
        specs['XGBoost'] = ('lexical', XGBClassifier(n_estimators=50 if quick else 120, max_depth=3, n_jobs=1, random_state=42, eval_metric='logloss'), {'learning_rate': [.05, .15]})
    except ImportError:
        optional = 'XGBoost not installed; install requirements-optional.txt to include it.'
    folds = 2 if quick else 5
    cv = list(StratifiedGroupKFold(folds, shuffle=True, random_state=42).split(X[fit], y[fit], groups[fit]))
    if any(len(set(y[fit][a])) < 2 or len(set(y[fit][b])) < 2 for a, b in cv):
        raise ValueError('Insufficient two-class domain groups for grouped CV')
    selected, results = {}, {}
    for name, (kind, estimator, grid) in specs.items():
        inputs = X if kind == 'lexical' else urls
        search = GridSearchCV(estimator, grid, scoring='average_precision', cv=cv, n_jobs=1, refit=True)
        search.fit(inputs[fit], y[fit])
        # FrozenEstimator never refits on calibration folds. Two folds accommodate
        # small samples; all out-of-fold scores are from the same frozen model.
        calibrated = CalibratedClassifierCV(FrozenEstimator(search.best_estimator_), method='sigmoid', cv=2)
        calibrated.fit(inputs[calibration], y[calibration])
        tune_p = calibrated.predict_proba(inputs[threshold_idx])[:, 1]
        threshold = threshold_for(y[threshold_idx], tune_p)
        selected[name] = {'model': calibrated, 'kind': kind, 'threshold': threshold}
        results[name] = {'cv_average_precision': float(search.best_score_), 'params': search.best_params_,
            'threshold_set': metrics_for(y[threshold_idx], tune_p, threshold)}
        print(f'{name}: grouped CV AP={search.best_score_:.4f}', flush=True)
    # Freeze model choice before touching held-out labels or scores.
    best_name = max(results, key=lambda n: results[n]['cv_average_precision'])
    for name, bundle in selected.items():
        inputs = X if bundle['kind'] == 'lexical' else urls
        probs = bundle['model'].predict_proba(inputs[test])[:, 1]
        results[name]['test'] = metrics_for(y[test], probs, bundle['threshold'])
    bundle = selected[best_name]
    reference = np.median(X[fit], axis=0)
    metadata_path = data_path.parent / 'provenance.json'
    provenance = json.loads(metadata_path.read_text()) if metadata_path.exists() else {'mode': 'user_supplied_unverified', 'rows': len(frame)}
    actual_hash = hashlib.sha256(data_path.read_bytes()).hexdigest()
    if provenance.get('dataset_sha256', actual_hash) != actual_hash:
        raise ValueError('Dataset hash differs from provenance; rebuild the dataset')
    bundle.update({'name': best_name, 'feature_names': FEATURE_NAMES, 'reference': reference,
        'dataset_mode': provenance['mode'], 'dataset_sha256': actual_hash, 'format_version': 3,
        'representation': 'scheme_neutral_v1'})
    temporary_model = model_path.with_suffix('.pending.joblib')
    joblib.dump(bundle, temporary_model, compress=3)
    temporary_model.replace(model_path)
    inputs = X if bundle['kind'] == 'lexical' else urls
    probs = bundle['model'].predict_proba(inputs[test])[:, 1]
    pred = probs >= bundle['threshold']
    predictions = pd.DataFrame({'url': urls[test], 'domain': groups[test], 'label': y[test], 'probability': probs, 'prediction': pred.astype(int)})
    predictions.to_csv(output / 'test_predictions.csv', index=False)
    predictions[pred != y[test]].to_csv(output / 'errors.csv', index=False)
    assignments = np.empty(len(urls), dtype=object)
    for name, idx in splits.items():
        assignments[idx] = name
    pd.DataFrame({'url': urls, 'domain': groups, 'partition': assignments}).to_csv(output / 'split_assignments.csv', index=False)
    report = {'dataset': provenance, 'dataset_sha256': actual_hash, 'splits': audit, 'domain_overlap': 0,
        'cv_folds': folds, 'selection_metric': 'grouped CV average precision on fit partition',
        'threshold_policy': 'Max precision with recall >= 0.90 on independent threshold partition; tie: largest threshold',
        'calibration': 'sigmoid on disjoint calibration-domain partition', 'best_model': best_name,
        'models': results, 'optional_dependency_note': optional, 'representation': 'scheme_neutral_v1'}
    (output / 'metrics.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    draw_charts(y[test], probs, pred, bundle, X[test], urls[test], output)
    write_error_analysis(predictions, provenance['mode'], output)
    print(json.dumps({'best_model': best_name, 'dataset': provenance['mode'], 'test': results[best_name]['test']}, indent=2))
    return report


def draw_charts(y, probs, pred, bundle, X, urls, output: Path) -> None:
    """Save final evaluation and descriptive permutation charts."""
    from sklearn.metrics import ConfusionMatrixDisplay
    fig, ax = plt.subplots(figsize=(5, 4))
    ConfusionMatrixDisplay.from_predictions(y, pred, display_labels=['benign-labelled', 'phishing'], ax=ax, colorbar=False)
    fig.tight_layout(); fig.savefig(output / 'confusion_matrix.png', dpi=150); plt.close(fig)
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    p, r, _ = precision_recall_curve(y, probs)
    axes[0].plot(r, p); axes[0].set(xlabel='Recall', ylabel='Precision', title='Held-out precision–recall')
    fpr, tpr, _ = roc_curve(y, probs)
    axes[1].plot(fpr, tpr); axes[1].plot([0, 1], [0, 1], '--'); axes[1].set(xlabel='False positive rate', ylabel='Recall', title='Held-out ROC')
    fig.tight_layout(); fig.savefig(output / 'curves.png', dpi=150); plt.close(fig)
    if bundle['kind'] == 'lexical':
        imp = permutation_importance(bundle['model'], X, y, scoring='average_precision', n_repeats=3, random_state=42)
        names, importance = FEATURE_NAMES, imp.importances_mean
        deviations = imp.importances_std
        title = 'Permutation importance (held-out AP decrease)'
    else:
        # Permute URL component families, preserving a network-free string model.
        parts = np.asarray([tuple(urlsplit(u if '://' in u else 'http://' + u)) for u in urls], dtype=object)
        baseline = average_precision_score(y, bundle['model'].predict_proba(urls)[:, 1])
        rng = np.random.default_rng(42)
        drops = []
        for column in range(5):
            repeats = []
            for _ in range(3):
                permuted = parts.copy()
                permuted[:, column] = parts[rng.permutation(len(parts)), column]
                perturbed = [urlunsplit(tuple(row)) for row in permuted]
                repeats.append(baseline - average_precision_score(y, bundle['model'].predict_proba(perturbed)[:, 1]))
            drops.append(repeats)
        names = ['scheme', 'host_and_port', 'path', 'query', 'fragment']
        importance, deviations = np.mean(drops, axis=1), np.std(drops, axis=1)
        title = 'URL-component permutation (held-out AP decrease)'
    summary = {'method': title, 'n_repeats': 3, 'features': [
        {'name': str(name), 'mean_ap_decrease': float(value), 'std': float(std)}
        for name, value, std in zip(names, importance, deviations)]}
    (output / 'global_importance.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    order = np.argsort(np.abs(importance))[-15:]
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.barh(np.asarray(names)[order], importance[order], color='#14b8a6')
    ax.set_title(title); fig.tight_layout(); fig.savefig(output / 'feature_importance.png', dpi=150); plt.close(fig)


def write_error_analysis(predictions: pd.DataFrame, mode: str, output: Path) -> None:
    """Describe actual mistakes without inferring page contents or intent."""
    errors = predictions[predictions.label != predictions.prediction]
    lines = [f'# Error analysis ({mode})', '', f'{len(errors)} errors among {len(predictions)} held-out URLs.',
        'URLs are inert strings in errors.csv; do not open them.', '',
        'Rows below describe lexical properties only; feed labels are not independently verified.', '']
    from .features import extract_features
    missed = errors[errors.label == 1]
    clean_root = sum(extract_features(u)['path_length'] <= 1 and extract_features(u)['num_sensitive_words'] == 0 for u in missed.url)
    lines.extend([f'{clean_root} of {len(missed)} false negatives have root-only paths and no credential keywords. This observed pattern is consistent with the source-shortcut limitation; it does not establish causation.', ''])
    for row in errors.head(12).itertuples():
        f = extract_features(row.url)
        kind = 'False negative' if row.label else 'False positive'
        lines.append(f'- {kind}: p={row.probability:.4f}; length={f["url_length"]}; path length={f["path_length"]}; HTTPS={bool(f["uses_https"])}; credential keywords={f["num_sensitive_words"]}.')
    if errors.empty:
        lines.append('No errors observed in this small split; this is not evidence of perfect real-world detection.')
    lines.extend(['', 'Source shortcut risk: Tranco examples are roots. Historical benign deep links reduce the original path shortcut, but inherited labels and collection differences remain.',
        'Tranco root strings assume HTTPS, but scheme-neutral model inputs prevent learning protocol-serialization differences. Human red flags remain independent.',
        'Next evaluation: independently labelled benign deep links, temporal holdout, and campaign-separated phishing.'])
    importance = json.loads((output / 'global_importance.json').read_text(encoding='utf-8'))
    leading = max(importance['features'], key=lambda item: item['mean_ap_decrease'])
    lines.extend(['', f'Largest observed permutation AP decrease: {leading["name"]} ({leading["mean_ap_decrease"]:.6f}). Importance is descriptive and was not used to tune the model.'])
    (output / 'error_analysis.md').write_text('\n'.join(lines), encoding='utf-8')


def main() -> None:
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--quick', action='store_true')
    args = parser.parse_args()
    train(quick=args.quick)
