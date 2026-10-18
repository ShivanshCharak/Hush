# Decider-Sec progress

This tracker records implementation status against the initial specification. Targets are locked before evaluation. Do not change targets after seeing results; record any necessary change in the append-only decision log in `docs/DECIDER-SEC-SPEC.md`.

## Current status

**Active phase: Phase 1 — Data and ground truth**  
**Overall: In progress — 7/8 evaluator checks pass; independent annotation is outstanding**  
**Last updated: 2026-10-18**

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
- [ ] Complete the independent 100-window annotation; require Cohen's kappa >= 0.70 and adjudicate disagreements.
- [ ] Freeze the test set and held-out streams, write `data/VERSION`, and pass all eight Phase 1 checks.

Current conversion: 151,011 records seen; 151,011 unique transaction IDs; 151,011 events written; 0 parse failures. The paper's 147,205 figure remains different, but the archive is intact and its verified count is used. CICIDS2017 contributes separate flow data and is not mixed into web-event windows. Stream and golden generation is implemented; independent annotation and final Phase 1 evaluation remain outstanding. See [README.md](README.md) and [the annotation handoff](data/annotations/README.md).

## Phase status

| Phase | Status | Exit gate headline |
|---|---|---|
| -1 Project foundation | In progress | Runtime, provenance, reproducibility, and locked-set controls documented |
| 1 Data and ground truth | In progress — provisional 600 windows and replay streams generated; second annotation pending | 600 windows, no session leakage, kappa >= 0.70, deterministic streams |
| 2 Baseline and Decider | Not started | Dev-only gates pass; hard-attack recall beats baseline by >= 20 points |
| 3 Gate and explainer | Not started | >= 21/24 episodes; <= 3 false alerts; grounding checks pass |
| 4 Dashboard and robustness | Not started | 3/3 deterministic demos; injection criteria pass |
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
