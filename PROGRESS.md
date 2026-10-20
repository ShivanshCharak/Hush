# Decider-Sec progress

This tracker records implementation status against the initial specification. Targets are locked before evaluation. Do not change targets after seeing results; record any necessary change in the append-only decision log in `docs/DECIDER-SEC-SPEC.md`.

## Current status

**Active phase: Phase 4 — Dashboard, demo, and injection robustness (prior phase exit criteria remain incomplete)**
**Overall: Phase 2 and Phase 3 remain incomplete; Phase 4 robustness/demo gates pass and the Next.js dashboard builds, while browser performance gates remain unmeasured**
**Last updated: 2026-10-20**

The original project brief, including detailed phase plans, evaluation rules, and target tables, is preserved in [docs/DECIDER-SEC-SPEC.md](docs/DECIDER-SEC-SPEC.md). The real-traffic dataset archive has been downloaded and its source, license, and hash are recorded in [README.md](README.md).

## Phase -1 — Project foundation and readiness

**Goal:** make the project structure, execution assumptions, data provenance plan, and evaluation controls explicit before creating datasets or implementing the detector.

- [x] Preserve the original specification as the baseline plan.
- [x] Create the project directory skeleton for Phases 1–5.
- [x] Add a developer-facing project README and this progress tracker.
- [ ] Confirm the intended repository checkout and its relationship to the current workspace. Current workspace is `/home/shivansh/Desktop/hush`; its Git root resolves to `/home/shivansh/Desktop`.
- [ ] Record Python/runtime versions, dependency management, local inference approach for Qwen3 1.7B, and demo machine hardware.
- [x] Select and download a documented real-world HTTP security dataset; record source citation, license, and archive hash in README.md.
- [ ] Define provenance metadata for mapping raw dataset records to derived windows and attack labels.
- [ ] Define fixed seed/config conventions and run artifact naming before the first generated dataset or evaluation.
- [ ] Decide whether AWS Bedrock is available for Phase 3 and document the local template fallback path.
- [ ] Verify the test-set and held-out-stream write-protection approach before those files are created.

**Exit gate:** all readiness items above are documented; repository location and ownership are unambiguous; data capture source and permissions are established; reproducibility conventions and evaluation run-counter policy are defined. The runtime and evaluation controls still need documenting; the user has authorized Phase 1 dataset acquisition to proceed in parallel.

## Phase 1 — Data and ground truth

**Status: In progress**

- [x] Download and verify the ModSecurity source archive.
- [x] Inspect the CSIC 2010 request dataset; reject it for the missing attack classes and remove the temporary download.
- [x] Add the relevant CICIDS2017 benign and brute-force flow CSVs as an auxiliary source, with row counts, hashes, and format limits documented in README.md.
- [x] Audit and document the ModSecurity archive/paper count discrepancy; use the archive's verified transaction count.
- [x] Extract 30 daily audit logs and convert them to normalized request events.
- [x] Record source citation, archive hash, output hash, counts, and parse failures.
- [x] Write the initial annotation guide and conservative WAF-tag mapping in `sim/annotate.md`.
- [x] Generate five replay streams, manifests, and provisional golden-window files with source provenance.
- [x] Owner reviewed and verified all 600 golden windows; status recorded in `data/golden/REVIEW_STATUS.md`.
- [x] Complete a blind second-pass labeling of 100 windows; evaluator reports 73 eligible pairs and Cohen's kappa 0.7834.
- [ ] Obtain independent human agreement if required for the project's reporting or release claims; the AI second pass is not methodologically independent.
- [x] Freeze the test set and held-out streams, write `data/VERSION`, and pass all eight automated Phase 1 checks.

Current conversion: 151,011 records seen; 151,011 unique transaction IDs; 151,011 events written; 0 parse failures. The paper's 147,205 figure remains different, but the archive is intact and its verified count is used. CICIDS2017 contributes separate flow data and is not mixed into web-event windows. The owner marked the 600 golden labels final after review. The evaluator passes all eight checks, including the AI second-pass agreement score; that score is not independent human validation because Codex helped create the original labels. See [README.md](README.md), [the owner review record](data/golden/REVIEW_STATUS.md), and [the second-pass review record](data/annotations/second_annotator_filled.REVIEW.md).

## Phase status

| Phase | Status | Exit gate headline |
|---|---|---|
| -1 Project foundation | In progress | Runtime, provenance, reproducibility, and locked-set controls documented |
| 1 Data and ground truth | Frozen; evaluator 8/8; AI second-pass kappa 0.7834; independent human agreement unverified | 600 windows, no session leakage, kappa >= 0.70, deterministic streams |
| 2 Baseline and Decider | In progress — Qwen3 8B run completed; hard-benign, kind accuracy, confidence, and latency gates fail; hard-attack check blocked by a dev-set count mismatch | Dev-only gates pass; hard-attack recall beats baseline by >= 20 points |
| 3 Gate and explainer | In progress — replay, injected fallback/call-parity, grounding, and human quality checks pass (revised mean 4.60/5); live Bedrock and latency checks remain outstanding | >= 21/24 episodes; <= 3 false alerts; grounding checks pass |
| 4 Dashboard and robustness | In progress — injection and paced-demo checks pass; 50k API query/reconciliation and frontend build pass; full-browser FPS, UI lag, and TTI gates remain unmeasured | 3/3 deterministic demos; injection criteria pass; all 14 dashboard checks required for phase exit |
| 5 Final evaluation and results | Not started | Locked test run once; targets met or misses documented |

## Locked final targets

These are the pre-build targets from the original brief. Measured values remain blank until reported from `eval/runs/*.json` in Phase 5.

| Metric | Target | Measured |
|---|---:|---|
| Attack recall | >= 0.90 (>= 87/96) | — |
| Benign false-speak rate | <= 0.05 (<= 6/120) | — |
| Precision | >= 0.90 | — |
| Hard-attack recall | >= 11/14 and >= 20 points above baseline | — |
| Hard-benign false-speak | <= 2/24 | — |
| Kind accuracy | >= 0.85 | — |
| Episode recall | >= 14/16 | — |
| False alerts on held-out streams | <= 2 total | — |
| Duplicate alerts per detected episode | <= 1.5 | — |
| Median time-to-detect | <= 40 events (~8 s) | — |
| Injection robustness | >= 29/30 attacks flagged; <= 1/20 benign false alerts; 0 canary leaks | — |
| Explanation grounding | 100% evidence IDs valid; >= 98% entities grounded | — |
| Decision latency | p50 <= 400 ms; p95 <= 1.2 s | — |

## Working rules

- Use dev data for tuning. Test windows and held-out streams stay untouched until the single Phase 5 run.
- Report counts with denominators for small subsets.
- Every evaluation writes a timestamped JSON artifact under `eval/runs/`.
- Any target adjustment is logged with its reason and affected metrics before proceeding.
- Keep phase work focused on its stated deliverables and evaluator.

## Phase 4 — Dashboard, demo, and injection robustness

Started 2026-10-20. Added a seeded 180-second demo timeline in [`demo/scenario.yaml`](demo/scenario.yaml), six payload templates per family in [`robust/payloads.yaml`](robust/payloads.yaml), and [`robust/inject.py`](robust/inject.py) to construct a deterministic 30-attack/20-benign injected corpus from dev windows. Prompt assembly escapes attacker-supplied `<DATA>` delimiters in event fields; Bedrock explanation inputs use the same explicit data wrapper, and explanations containing the configured `EXPLANATION_CANARY` are rejected. The Next.js App Router/Tailwind UI has a black-and-white theme, a line-series request chart, a virtualized event table, and compact alert cards with evidence IDs and gate reasons. FastAPI/DuckDB supports snapshot ingestion and incremental JSONL tailing. [`eval/phase4_eval.py`](eval/phase4_eval.py) passes its dev-only gates in [`eval/runs/phase4-20261020T050608Z.json`](eval/runs/phase4-20261020T050608Z.json): 30/30 silence-injected attacks still alert, 0/20 benign page-oncall windows alert, 0/10 canary leaks, and 3/3 identical paced replays (180.059–180.107 s; 900 events; credential-stuffing, SQLi, XSS alert order). A 20x replay emitted all 900 events and 45 trace windows in 9.246 s. API checks reconciled 900 events, 45 windows, and three alerts; a 50k-row synthetic DuckDB benchmark reconciled all 10 histogram filter combinations with p95 71 ms, and 200-row page p95 was 41 ms. The browser preview renders the 200-row first page and all three alert cards, with evidence IDs and gate reasons; `npm run lint` and `npm run build` pass. The histogram maximum-timestamp bucket boundary and DuckDB reader/writer configuration conflicts found during validation are fixed. Full-client UI lag during 5/20x replay, 50k-row FPS, filter-to-repaint, measured TTI, and reload-deduplication in the browser have not been measured, so the 14-check Phase 4 exit gate is not yet claimed as passed. Locked test and held-out stream files were not used.

## Phase 2 — Baseline, pre-filter, and Decider

## Phase 3 — Gate, explainer, and pipeline

Implemented `gate/gate.py` with a 30-second per-source/kind cooldown, fingerprint deduplication, configurable confidence threshold, and a six-alert rolling 10-minute budget. `pipeline/run.py` processes event streams in 20-event windows, applies the event prefilter, calls the rules baseline by default (or Ollama with `--model`), gates every decision, and records a JSONL trace. Emitted alerts receive deterministic evidence-grounded template explanations. Optional Bedrock explanation is enabled with `--bedrock` and `BEDROCK_MODEL_ID`; it only receives evidence events from emitted alerts, retries once, and falls back to the template.

The dev-only evaluator is [`eval/phase3_eval.py`](eval/phase3_eval.py). Its latest run [`eval/runs/phase3-20261020T043100Z.json`](eval/runs/phase3-20261020T043100Z.json) uses the rules baseline and template mode, not Ollama or live Bedrock: 24/24 attack episodes detected, 1 false alert, 0 duplicates, median 20 events to detect, 0 budget violations, 0 unaccounted speaks, and 100% entity grounding. An injected explainer confirms calls match emitted alerts, and five forced timeouts produce five template fallbacks. Human review of the first template averaged 3.82/5, below target. The revised kind-specific action recommendations were rated across all 20 alerts: category means are correct kind 4.60, evidence use 4.80, and actionability 4.40, for an overall 4.60/5. See the [completed rating sheet](eval/runs/phase3-20261020T043100Z-actionability-review.jsonl). The manual quality target passes; live Bedrock parity/latency and event-to-alert latency checks remain outstanding. Run `python eval/phase3_eval.py` to reproduce; test and held-out streams are not read.

**Latest completed model run (2026-10-20):** [`eval/runs/phase2-20261020T033832Z.json`](eval/runs/phase2-20261020T033832Z.json), Qwen3 8B, 360/360 windows completed (153 resumed from checkpoint). On 324 labeled speak/silent windows it recorded 125/144 attack recall (86.8%), 7/180 benign false alerts (3.9%), and 125/132 precision (94.7%). Schema validity passed without repairs (360/360), and pre-filter passed (96.7% event drop; 24/24 attack episodes preserved). The run detected 29/29 hard attacks, but that check is blocked because the locked target expects 21 hard attacks and this dev set contains 29. Remaining misses: hard-benign false alerts 7/36 (target <=5), kind accuracy 96/125 (76.8%; target >=80%), confidence AUROC 0.9008 (target >=0.93), and latency. The evaluator's gated latency metric (including 200 zero-latency skipped windows) is p50 0s / p95 44.2s; its model-call-only diagnostic is p50 31.8s / p95 48.8s. The locked target is p50 <=0.4s / p95 <=1.2s per window, so Phase 2 is therefore **not passed**. The run used an 8B model on the local host; the observed `ollama ps` snapshot showed a 6.0 GB runner split 54% GPU / 46% CPU on a 7.1 GiB RAM machine, with 2.1 GiB swap in use. This explains the observed latency pressure but does not satisfy or waive the locked latency target. The same run's rules baseline had the same speak counts (125/144 attacks and 7/180 benign), so these detection counts do not establish a recall/false-alert gain from the model. Kind classification and confidence are model-dependent. The 8B result is a documented dev result, not a Phase 2 pass.

**Historical Qwen3 1.7B evaluation:** the earlier runs below predate the current completed Qwen3 8B result summarized above.

- [x] Implement a transparent rules baseline with 60-second auth counts, distinct usernames, 4xx/path diversity, and web-attack signatures.
- [x] Implement a pre-filter that drops at least 90% of dev-stream events and preserves every attack episode.
- [x] Implement the code-computed 20-event count header, untrusted-data prompt wrapper, output schema, and Ollama structured-output adapter.
- [x] Add a Phase 2 evaluator limited to dev windows and streams 01–03.
- [ ] Run all model-dependent Phase 2 checks with Qwen3 1.7B and meet the locked targets.

Latest run: [`eval/runs/phase2-20261019T160457Z.json`](eval/runs/phase2-20261019T160457Z.json). Rules baseline on 324 scored dev windows: attack recall **122/144 (84.7%)**, benign false-speak **7/180 (3.9%)**, precision **122/129 (94.6%)**. The pre-filter drops **28,996/30,000 (96.7%)** of dev-stream events and preserves **24/24** attack episodes. Qwen completed all **360** windows with schema-valid output, but spoke on **all 180 benign and all 144 attack windows**: attack recall 100%, benign false-speak 100%, precision 44.4%, hard-benign false speaks 36/36, kind accuracy 48/144 (33.3%), confidence AUROC 0.789, and latency p50 8.66 s / p95 12.49 s. Thus Phase 2 remains incomplete. The latest prompt revision makes silence criteria and attack thresholds explicit; the evaluator now records per-window predictions for dev-only diagnosis on the next run.

Follow-up: [`eval/runs/phase2-20261019T161059Z.json`](eval/runs/phase2-20261019T161059Z.json) stopped on the first response, not on timeout. Qwen returned `speak=false` alongside `kind=xss` and an evidence ID. The adapter now fails closed to silence for invalid or contradictory outputs, records each repair, fails the schema-validity gate when a repair was needed, and continues computing classification metrics. A repaired response does not count as schema-valid.

**Offline diagnostic (2026-10-20):** Recomputing the current detailed `pattern_checks` over `data/golden/dev.jsonl` covers 122/144 attack windows and fires on 7/180 labeled-silent windows (plus 28/36 ambiguous windows). The 122 attack coverage is 84.7%, just below the 85% Phase 2 recall gate, so enforcing a strict confirmed-pattern gate now would suppress most false alerts but narrowly miss attack recall. The 2026-10-19 run with 174 benign false speaks predates the detailed pattern checks in the prompt; its artifact has no raw model text or per-window checks, so it cannot establish whether Qwen ignored those checks. The prompt now uses balanced `<DATA>...</DATA>` delimiters, and new run artifacts retain raw model text and per-window `pattern_checks` for diagnosis. No new model run has yet validated these changes.

**Phase 2 follow-up (2026-10-20):** The saved 2026-10-20 Qwen run did include detailed checks; among 99 false alerts, 92 selected a kind with no confirmed supporting check. An offline gate replay produced 122/144 attack hits and 7/180 false alerts; adding a narrowly targeted SQL tautology signature (`AND/OR n=n`) identifies three additional labeled attack windows with no new labeled-silent hits, bringing the rule-only dev result to 125/144 attacks (86.8%) and 7/180 false alerts (3.9%). The regex and pattern-check version were updated, and inference now skips unconfirmed windows and restricts kinds/citations to code-confirmed evidence. No model evaluation has run against this gated implementation yet. The locked spec defines 21 dev hard attacks (20 low-and-slow stuffing plus one encoded injection), but current labels put 20 simulated stuffing and 9 ModSecurity SQLi windows in dev (29 total); test has 6 hard SQLi windows. Preserve the locked target and report this split mismatch rather than changing it after evaluation.

The updated inference also requests an explicit 8192-token context and records prompt-evaluation token counts, raw `speak`-token alternatives, and raw JSON output. Confidence is now derived from the true-vs-false log-probability difference when both alternatives are present; repaired outputs can retain confidence from the unmodified model boolean. These measurements still need a local Ollama run.

**Local run update (2026-10-20):** The fresh run `eval/runs/phase2-20261020T005151Z.json` passed the baseline and pre-filter checks, then timed out after 6/360 Decider windows at `modsec:18-Aug-2025:003440` (30-second per-request timeout). The first keyboard interruption was user-cancelled inference, not an evaluator failure. The model had answered earlier windows, so Ollama was reachable. To reduce long-prompt latency, the model view now omits repeated/empty fields and full timestamps, keeping only classification-relevant event fields and relative `t_s`. The prompt format version was incremented, which intentionally invalidates the older checkpoint; start once with `--fresh`, then omit `--fresh` on retries to resume compatible checkpoints. The compact-view source-ID mapping was also corrected so evidence citations still map back to dataset IDs. A full local model run is still required to measure the change.

The seven baseline false alerts are all labeled hard-benign approved-internal-scanner windows. The new kind gate can cap unsupported false alerts, but these scanner windows satisfy the current scanner rule and remain a known hard-benign failure unless trusted authorization context is supplied; do not hardcode a benchmark IP or user-agent as a detector rule.

Latest complete run: [`eval/runs/phase2-20261019T171036Z.json`](eval/runs/phase2-20261019T171036Z.json) scored all 360 dev windows. The model reached 126/144 attack recall (87.5%), but false-spoke on 108/180 benign windows (60%). It needed 26 schema repairs; kind accuracy was 49/126 (38.9%), confidence AUROC was unavailable because repaired outputs have no confidence, and p50/p95 latency was 8.73/12.67 seconds. Investigation showed many false alerts cited ordinary events without visible attack evidence. The prompt has now been tightened to disregard IDs and confidence as evidence, require thresholds to be met by events sharing a source, and require visible payload or behavioral support for the selected kind. This is a dev-only prompt iteration; targets and locked data were not changed. Rerun Phase 2 to measure its effect.

Follow-up run `phase2-20261019T183653Z.json` completed 316/360 windows before an Ollama request timed out at `sim-dev-priv_esc-0007`; the run artifact does not contain those 316 individual predictions, so it cannot be resumed. The evaluator now writes a fingerprinted checkpoint after each successful window and automatically resumes it on the next same-model, same-prompt, same-data run. Use `--fresh` to discard a compatible checkpoint. No model metrics were produced by the timed-out run.

Latest full run, `phase2-20261019T194328Z.json`, completed all 360 windows. The revised prompt reached 133/144 attack recall (92.4%) but false-spoke on 174/180 benign windows (96.7%); 135 of the 174 false alerts were called brute force. Hard-benign false speaks were 33/36, kind accuracy 60/133 (45.1%), and 10 responses needed schema repair. Confidence AUROC was unavailable, and p50/p95 latency was 8.88/12.68 seconds. The rules baseline remains much quieter at 122/144 attack recall and 7/180 benign false speaks. Requiring both the model and baseline to alert would lower false speaks to 7/180 but also lower attack recall to 113/144, below the Phase 2 gate; this is not being adopted as a passing solution. The next inference now receives computed per-pattern counts and confirmations in the header, while raw source event IDs are replaced by local positions and mapped back for citations. Confidence is now consistently represented as P(speak=true), and partial AUROC is reported with coverage while the gate still requires complete coverage. This next run has not yet been performed; targets and evaluation data remain unchanged.

Data note: the dev split contains **29** windows marked as hard attacks, while the Phase 2 target table expects **21**. The current baseline detects **26/29** of them. The evaluation records this denominator mismatch rather than silently changing labels or the target. The locked test split has not been read or changed.
