# Phase 1 labeling guide

## Unit of labeling

A window contains 20 consecutive events from one stream and one source session. Do not join across a daily ModSecurity session boundary. For the public dataset, `session_id` is the source date. Use non-overlapping 20-event slices for the initial candidate pool so a request is not repeated in many examples. Window selection and split assignment must be deterministic and recorded in the manifest.

Annotate each window with `speak`, `kind`, `hard`, and a short evidence note. Use only `none` for a reviewed benign window. Use `ambiguous` when evidence is mixed, insufficient, or the annotators cannot agree; ambiguous windows are reported separately and excluded from scored/gated counts.

## Source data limits

The ModSecurity archive contains requests that triggered at least one WAF rule. A WAF hit is evidence that a rule matched; it is not by itself ground truth that the request is malicious or that an alert is useful. Do not derive benign examples from this archive. Build benign and hard-benign windows from the simulator or an explicitly labeled benign dataset.

The normalized source file preserves WAF metadata for annotation and provenance. **Never include these fields in model input or evaluation features:** `source_dataset`, `source_record_marker_id`, `source_unique_id`, `waf_flagged`, or `modsecurity`. The prompt/window builder must project source rows down to the agreed web-event schema. Keep the excluded fields in a label-provenance sidecar so every derived example remains traceable.

The converter does not retain raw request bodies. If a label depends on a body payload, consult the corresponding raw audit record using `source_unique_id`; do not infer from missing data. `bytes: null` means the response did not provide a usable Content-Length value.

## WAF-tag mapping for candidate attack windows

These are candidate signals for human review, not automatic gold labels. Rule IDs and tags can overlap, and a rule may be noisy or generic.

| Decider-Sec kind | Candidate source evidence | Labeling rule |
|---|---|---|
| `sqli` | `attack-sqli` or `OWASP_CRS/WEB_ATTACK/SQL_INJECTION` | Label only when the matched request evidence is consistent with SQL injection. |
| `xss` | `attack-xss` or `OWASP_CRS/WEB_ATTACK/XSS` | Label only when the matched request evidence is consistent with cross-site scripting. |
| `path_traversal` | `OWASP_CRS/WEB_ATTACK/DIR_TRAVERSAL` | Require traversal evidence in the request or the rule's matched data. Do not map file-inclusion tags alone to path traversal. |
| `scanner_recon` | `attack-reputation-scanner` or `OWASP_CRS/AUTOMATION/SECURITY_SCANNER` | Require an explicit scanner rule or clear reconnaissance pattern. Generic protocol violations and bot/user-agent matches alone are insufficient. |
| `brute_force` | No direct authentication outcome in this source | Generate and label from simulator/auth events. |
| `credential_stuffing` | No username/password outcome or account sequence in this source | Generate and label from simulator/auth events. |
| `priv_esc` | No authorization, role, or ownership context in this source | Generate and label from simulator scenarios. |
| `none` | No evidence of attack in a reviewed benign source | Use simulator or another labeled benign source; never use an untagged/weakly tagged ModSecurity row as benign by default. |

The archive has many `attack-lfi` / `WEB_ATTACK/FILE_INJECTION` matches. Treat these as **file-inclusion candidates**, not automatically as `path_traversal`; map them to the project taxonomy only when the request and matched data provide the required traversal evidence. If the evidence cannot be inspected or does not fit a listed kind, use `ambiguous`.

## Window decision rules

1. Review the 20 events together with the code-computed header. Do not let WAF rule metadata decide the label by itself.
2. For a clear attack episode, set `speak: true` and assign exactly one supported `kind`. Cite stable event IDs that show the behavior.
3. If multiple attack kinds are present, assign one only when one is clearly the episode's primary behavior; otherwise label `ambiguous`.
4. Set `hard: true` only for the predeclared hard cases: low-and-slow credential stuffing or encoded SQLi/XSS. Record which property makes the case hard. This public archive cannot supply low-and-slow credential-stuffing labels because it has no authentication outcomes.
5. Set `speak: false`, `kind: none` only for reviewed benign traffic. Clearly labeled hard-benign scenarios must also come from the simulator or another benign source.
6. Keep the original evidence and provenance in the annotation record. Do not place annotator notes or gold labels in the model-visible event payload.

## Split and agreement

Split by source session before selecting examples. For the ModSecurity source, the daily source date is the session key. A date may appear in dev or test, never both. Keep the test sessions and streams 04–05 locked until the single Phase 5 run. Use fixed seeds and record selected session IDs and event ranges.

A second annotator independently labels the required 100 stratified windows. Compute Cohen's kappa on the binary `speak`/`silent` labels; ambiguous examples are excluded from this calculation. The Phase 1 gate requires kappa >= 0.70. Resolve disagreements by revising the guide and relabeling before freezing the test data.

Generate the blind packet as `data/annotations/second_annotator_template.jsonl` with `python sim/build_golden.py`. It contains 40 attack, 40 benign (20 ordinary and 20 hard), and 20 ambiguous candidates from the dev split. Fill it using [`data/annotations/README.md`](../data/annotations/README.md), save as `second_annotator_filled.jsonl`, then run `python eval/phase1_eval.py`. The provisional key is stored separately and must not be used by the second annotator.

## Current tag-count snapshot

Counts below are events with at least one matching parsed tag, not validated attack labels or window counts. Categories overlap.

| Candidate evidence | Events |
|---|---:|
| SQL injection tags | 4,338 |
| XSS tags | 278 |
| Directory-traversal tags | 1,021 |
| File-inclusion/LFI tags | 52,104 |
| Explicit scanner tags | 376 |

This source has no direct evidence for brute force, credential stuffing, privilege escalation, or benign traffic. The verified archive contains 151,011 unique transaction IDs while the paper reports 147,205 requests. No duplicate transactions explain the difference; retain the full archive and use its reproducible count while preserving the unresolved source discrepancy in the manifest.
