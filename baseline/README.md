# Rules baseline

The production baseline scores one 20-event window at a time. It applies per-source brute force (five failures for one account in 60 seconds, no matching success), distributed brute force (one username across at least three IPs in 60 minutes, no success), and distributed credential stuffing (at least four failed usernames across at least two IPs, four failures, and success/attempt ratio <=0.25 on authentication endpoints in 60 minutes). It also checks 4xx rate and endpoint diversity, normalized payload signatures, sensitive-path probes, and profile-ID enumeration. Rule decisions include a kind, evidence event IDs, and an inspectable reason.

Payload normalization runs before SQLi/XSS/traversal matching: up to three repeated URL-decode passes, HTML entity and Unicode escape decoding, SQL comment stripping, then whitespace collapse. The exact normalization helpers are in `baseline/normalization.py`.

Run the current dev-only rules and stream evaluation from the repository root:

```sh
source venv/bin/activate
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src:$(pwd)"
python -m eval.rules_dev_eval
```

Thresholds are in `baseline/rules.py` and are recorded in each run artifact. The held-out test split and streams 04–05 are not read by this evaluator. `eval/phase2_eval.py` is retained as historical local-model study code.
