# Error analysis (public_feeds_with_historical_benign)

24 errors among 352 held-out URLs.
URLs are inert strings in errors.csv; do not open them.

Rows below describe lexical properties only; feed labels are not independently verified.

6 of 9 false negatives have root-only paths and no credential keywords. This observed pattern is consistent with the source-shortcut limitation; it does not establish causation.

- False positive: p=0.9795; length=20; path length=1; HTTPS=True; credential keywords=0.
- False positive: p=0.8791; length=26; path length=1; HTTPS=False; credential keywords=0.
- False positive: p=0.8048; length=31; path length=1; HTTPS=False; credential keywords=0.
- False positive: p=0.2260; length=36; path length=24; HTTPS=False; credential keywords=0.
- False positive: p=0.3836; length=27; path length=1; HTTPS=True; credential keywords=0.
- False negative: p=0.0681; length=60; path length=1; HTTPS=True; credential keywords=0.
- False positive: p=0.1534; length=24; path length=1; HTTPS=False; credential keywords=0.
- False negative: p=0.0102; length=87; path length=51; HTTPS=False; credential keywords=0.
- False positive: p=0.2300; length=18; path length=1; HTTPS=True; credential keywords=0.
- False negative: p=0.0302; length=29; path length=1; HTTPS=False; credential keywords=0.
- False negative: p=0.0256; length=45; path length=23; HTTPS=False; credential keywords=0.
- False positive: p=0.5756; length=48; path length=1; HTTPS=False; credential keywords=0.

Source shortcut risk: Tranco examples are roots. Historical benign deep links reduce the original path shortcut, but inherited labels and collection differences remain.
Tranco root strings assume HTTPS, but scheme-neutral model inputs prevent learning protocol-serialization differences. Human red flags remain independent.
Next evaluation: independently labelled benign deep links, temporal holdout, and campaign-separated phishing.

Largest observed permutation AP decrease: host_and_port (0.686992). Importance is descriptive and was not used to tune the model.