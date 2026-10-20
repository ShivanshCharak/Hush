# Rules baseline

The baseline scores one 20-event window at a time. It uses failed-login counts per source over a rolling 60-second interval, distinct usernames, 4xx rate and endpoint diversity, decoded request signatures, sensitive-path probes, and profile-ID enumeration. Rule decisions include a kind, evidence event IDs, and an inspectable reason.

Run the Phase 2 dev-only evaluation from the repository root:

```sh
source venv/bin/activate
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src:$(pwd)"
python eval/phase2_eval.py --skip-model
```

Thresholds are in `baseline/rules.py` and are recorded in each run artifact. The held-out test split and streams 04–05 are not read by this evaluator.
