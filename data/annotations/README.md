# Phase 1 annotation handoff

`second_annotator_template.jsonl` is the blind 100-window review packet. It contains 40 attack candidates, 40 benign candidates (20 ordinary and 20 hard benign), and 20 ambiguous candidates. It shows event payloads and blank response fields, but no proposed labels.

For every row, preserve `review_id` and `events`, then fill:

- `label`: `speak`, `silent`, or `ambiguous`.
- `kind`: `brute_force`, `credential_stuffing`, `sqli`, `xss`, `path_traversal`, `priv_esc`, `scanner_recon`, `none`, or `ambiguous`.
- `evidence_event_ids`: event IDs that support your decision.
- `note`: a short reason, especially for ambiguous or disagreed cases.

Use `silent` + `none` for benign examples. Use `speak` + an attack kind only when the events support that alert. Use `ambiguous` + `ambiguous` when the evidence is insufficient or mixed. The 20 ambiguous candidates are excluded from binary Cohen's kappa.

Save the completed JSONL as `second_annotator_filled.jsonl` in this directory. Do not inspect `second_annotator_key.json` while labeling; it maps the blind review IDs to provisional labels and split rows. Then run `python eval/phase1_eval.py`. The agreement gate requires at least 60 non-ambiguous pairs and Cohen's kappa >= 0.70.

The real ModSecurity candidates in `real_candidates.jsonl` were screened using explicit WAF tags. Their proposed kinds are provisional because a WAF match can be noisy. Review the visible request fields and evidence IDs; do not assume the proposal is correct. WAF-only fields stay outside the model-visible events.
