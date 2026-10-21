# Same-data detector ablation

The runner evaluates A–E over exactly the three manifest-declared dev streams 01–03, split into the same non-overlapping 20-event windows and passed through the same `AlertGate` settings. It reports attack-episode recall, hard-benign episode false speaks, false alerts outside attack episodes, emitted alerts, and kind counts. It does not read the golden test split or held-out streams 04–05.

| Variant | Definition |
|---|---|
| A — Naive frozen rules | Historical rules implementation at the parent of commit `489e860b`, with allowlist authorization disabled for the ablation. This source has per-source rules and its then-current URL decoding. |
| B — Cross-IP and credential stuffing | Current rules plus the same-username cross-IP rule and distinct-username/IP stuffing rule; use the historical URL-only decoder and disable authorization. |
| C — Normalization | B plus the frozen normalizer (up to three URL-decode passes, HTML entity and Unicode escape decoding, SQL-comment stripping, whitespace collapse); authorization remains disabled. |
| D — Allowlist | C plus the config-backed, scope- and expiry-aware authorized-source allowlist. |
| E — Bedrock explanations | D decisions with explanation-only Bedrock calls. `--dry-run` uses deterministic templates and records Bedrock as pending; `--real-bedrock` is guarded by `HUSH_BEDROCK_CONFIRMED=1` and `BEDROCK_MODEL_ID`. Explanations cannot change alert inclusion. |

All variants share the current alert gate, input windows, labels, and score calculation. The runner records both its variant definitions and a config snapshot. The initial dry run is template-only; no AWS request is made.
