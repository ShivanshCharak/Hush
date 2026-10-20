# Baseline implementation notes

`rules.py` is the transparent rules-only comparator. `inspect_window()` emits the highest-scoring rule, evidence IDs drawn from input events, a heuristic confidence, a reason, and count features. It does not read dataset labels or provenance.

Authentication thresholds use event timestamps and a rolling 60-second window. A window containing a successful login for an account suppresses the single-account brute-force rule for that same account. Request payload checks decode up to three percent-encoding layers before matching SQL injection, XSS, or traversal signatures. Scanner rules use sensitive paths, scanner user agents, or a high 4xx rate paired with path diversity. The profile enumeration heuristic is a visible proxy for the project's IDOR/forced-browsing class; it should not be interpreted as proof of unauthorized access.

The Phase 2 evaluator uses only `data/golden/dev.jsonl` and streams 01–03. Keep thresholds and target values fixed after reporting results; record any tuning in `PROGRESS.md` and the run artifacts.
