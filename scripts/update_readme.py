"""Generate the results block directly from metrics.json; --check detects drift."""
import argparse
import json
from pathlib import Path


def results_block(metrics: dict) -> str:
    mode = metrics['dataset']['mode']
    best = metrics['best_model']
    lines = [f'**Dataset: `{mode}` — {metrics["dataset"]["rows"]} URLs.**', '',
        '**Synthetic results are pattern-recovery demonstrations, not real-world accuracy.**' if mode == 'synthetic' else '**Public-source study only; inherited historical labels, weak Tranco labels and source bias prevent real-world accuracy claims.**', '',
        f'Dataset SHA-256: `{metrics["dataset_sha256"]}`.', '',
        '| Model | Grouped CV AP | Test precision | Test recall | Test F1 | Test AP | Test ROC-AUC | Threshold |',
        '|---|---:|---:|---:|---:|---:|---:|---:|']
    for name, item in metrics['models'].items():
        t = item['test']
        lines.append(f'| {name} | {item["cv_average_precision"]:.4f} | {t["precision"]:.4f} | {t["recall"]:.4f} | {t["f1"]:.4f} | {t["pr_auc_average_precision"]:.4f} | {t["roc_auc"]:.4f} | {t["threshold"]:.6f} |')
    t = metrics['models'][best]['test']
    tuned = metrics['models'][best]['threshold_set']
    lines.extend(['', f'Selected by training-domain CV AP: **{best}**. Test FPR: **{t["false_positive_rate"]:.4f}**. Descriptive test FPR at 90% recall: **{t["fpr_at_90pct_recall_descriptive"]:.4f}**. Brier score: **{t["brier_score"]:.4f}**.', '',
        f'The chosen threshold achieved recall **{tuned["recall"]:.4f}** on threshold-tuning domains and **{t["recall"]:.4f}** on test domains. The tuning target is not a guarantee on unseen domains.', '',
        f'Confusion matrix (rows: true 0/1; columns: predicted 0/1): `{t["confusion_matrix"]}`.', '',
        '| Partition | Rows | Registered domains | Phishing |', '|---|---:|---:|---:|'])
    for name, split in metrics['splits'].items():
        lines.append(f'| {name} | {split["rows"]} | {split["domains"]} | {split["phishing"]} |')
    lines.extend(['', f'Cross-partition domain overlap: **{metrics["domain_overlap"]}**. CV folds: **{metrics["cv_folds"]}**.', '',
        'Numbers are rounded for display; outputs/metrics.json contains full precision. No test labels were used for model or deployment-threshold selection.'])
    return '\n'.join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    path = Path('README.md')
    text = path.read_text(encoding='utf-8')
    block = results_block(json.loads(Path('outputs/metrics.json').read_text(encoding='utf-8')))
    start, end = '<!-- RESULTS:START -->', '<!-- RESULTS:END -->'
    before, after = text.split(start)[0], text.split(end)[1]
    generated = before + start + '\n' + block + '\n' + end + after
    if args.check:
        if generated != text:
            raise SystemExit('README metrics are stale; run python tasks.py report')
        print('README results match outputs/metrics.json.')
    else:
        path.write_text(generated, encoding='utf-8')
        print('README results generated from outputs/metrics.json.')


if __name__ == '__main__':
    main()
