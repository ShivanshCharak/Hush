# Decider-Sec

Decider-Sec is a small local-model log monitor that decides whether a 20-event window warrants an alert. A gate limits interruptions, and Bedrock explains only alerts that pass the gate.

## Project status

Phase 1 artifacts are frozen and its evaluator passes 8/8 checks; the second-pass kappa was produced by the same assistant that helped create the initial labels, so independent human agreement remains unverified. Phase 2 baseline and inference scaffolding are in progress. See [PROGRESS.md](PROGRESS.md) for status and [docs/DECIDER-SEC-SPEC.md](docs/DECIDER-SEC-SPEC.md) for phase criteria and locked targets.

## Setup

The local inference adapter targets Ollama with Qwen3 1.7B. See [`decider/README.md`](decider/README.md) for setup and configuration, including the per-window request timeout. Optional AWS Bedrock setup is planned for Phase 3.

## Planned commands

The project specification calls for `make data`, `make baseline`, `make decide`, `make pipeline`, `make demo`, and `make eval`. These commands will be added with their corresponding phases; they are not available yet.

## Phase 1 real-traffic dataset

The project uses the public **A Thirty-Day Dataset of Malicious HTTP Requests Blocked by OWASP ModSecurity on a Production Web Server** as its real-world HTTP attack-log source. The source paper reports 147,205 requests over 30 days; entries are anonymized ModSecurity audit logs of requests that triggered OWASP Core Rule Set rules. The dataset includes SQL injection, XSS, file-inclusion, scanner, and malformed/evasive request examples. It is request-level WAF log data, not a complete benign-plus-attack stream, so Phase 1 still needs to derive attack windows and combine them with generated benign traffic according to the dataset plan.

- **Downloaded archive:** [`sim/capture/external/modsecurity-zenodo-17178461/owasp.zip`](sim/capture/external/modsecurity-zenodo-17178461/owasp.zip)
- **Zenodo record:** [10.5281/zenodo.17178461](https://zenodo.org/records/17178461)
- **Dataset paper:** [Lucz & Forstner, *Data* 10(11), 186 (2025)](https://doi.org/10.3390/data10110186)
- **License:** Creative Commons Attribution 4.0 International (CC BY 4.0), as stated by the paper. Cite the dataset and paper when reusing it.
- **Archive verification:** Zenodo MD5 `95b7a8237abc163d8ca31e49f7318efd`; local SHA-256 `3c4c976f58cd2da61a543a237ede770529ceee59cdb09295a5998d420a8b30b8`.

The archive has been extracted to `sim/capture/external/modsecurity-zenodo-17178461/raw/` and converted to project-shaped web events. The converter is [`sim/convert_modsecurity.py`](sim/convert_modsecurity.py); rerun it with `python sim/convert_modsecurity.py`. It writes one JSON object per request to `data/external/modsecurity_events.jsonl`, with the short record marker ID, actual unique ModSecurity transaction ID, daily session, WAF rule metadata (including matched data), and stable event IDs. It writes `data/external/modsecurity_events.manifest.json` with source/output hashes and per-session counts, plus `data/external/modsecurity_events.errors.jsonl` (empty for this conversion).

Conversion summary: **151,011 records** across **30 daily sessions**, **0 parse failures**. The source paper reports 147,205 requests, a difference of 3,806. The local archive contains 151,011 unique ModSecurity transaction IDs; eight short record-marker IDs repeat but are not duplicate transactions. The mismatch cannot be reconciled from the archive itself, so the manifest records both counts and the project retains the complete verified archive rather than removing records to force the paper count. The normalized file is 115 MB; extracted raw logs are about 380 MB. `bytes` is null when the response has no Content-Length header. `waf_flagged` records that ModSecurity logged the request; the converter does not infer the project’s attack kind from a rule ID. The tag-to-kind candidate mapping and window-label rules are in [`sim/annotate.md`](sim/annotate.md). The owner marked the golden set final after reviewing it; a separate independent human review remains unverified.

## Auxiliary brute-force and benign flow data

Three CICIDS2017 machine-learning CSVs are preserved under [`sim/capture/external/cicids2017/`](sim/capture/external/cicids2017/README.md). The selected days contain benign traffic, FTP/SSH Patator brute force, and Thursday web brute force/XSS/SQL injection. The official CIC page also describes benign background traffic and the labeled attacks; it links the original dataset paper for citation. The files were fetched from the public [Hugging Face CIC-IDS2017 mirror](https://huggingface.co/datasets/muzom/CIC-IDS2017) because the official download page currently routes through a download form. Exact per-file row counts and SHA-256 hashes are in the dataset README.

These records add **15,342 brute-force flows** and **1,130,178 benign flows** (plus 652 XSS and 21 SQL injection flows). They do **not** provide credential-stuffing or privilege-escalation labels. They are network-flow feature rows, not web/auth log events; this ML CSV variant has no timestamps, source/destination IPs, or HTTP request fields. Keep them separate from `modsecurity_events.jsonl` and do not use them as ordered golden windows. They are useful as an auxiliary labeled flow dataset, but adding them to the primary windowed log set requires a compatible flow-event schema and sequence source.

- [Official CICIDS2017 description and attack schedule](https://www.unb.ca/cic/datasets/ids-2017.html)
- Citation: Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, “Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization,” ICISSP 2018.
- **CSIC 2010 inspection:** downloaded and checked the raw request archive. It labels only `Valid`/`Attack`; despite containing login endpoint requests, it has no timestamps or source identities and no labeled brute force, credential stuffing, or privilege escalation. It was removed instead of being added to the project dataset.

## Phase 1 data build

The deterministic simulator is configured in [`sim/scenarios.json`](sim/scenarios.json). Generate the artifacts in this order:

```bash
source venv/bin/activate
python sim/build_streams.py
python sim/select_real_windows.py
python sim/build_golden.py
python sim/finalize_data.py
python eval/phase1_eval.py
```

The current build creates five replay streams with 10,000 events each and 40 attack plus 15 hard-benign episodes. The golden files have the target class counts and include 120 ModSecurity attack windows split by source day. The project owner reports reviewing and verifying all 600 golden windows; their labels are marked final by owner review in [`data/golden/REVIEW_STATUS.md`](data/golden/REVIEW_STATUS.md). A blind AI second pass yields 73 eligible pairs and Cohen's kappa 0.7834; all eight automated checks pass. Because Codex helped create the original labels, this is not independent human agreement; see the [review record](data/annotations/second_annotator_filled.REVIEW.md). `sim/finalize_data.py` locks the test file and held-out streams and writes hashes to `data/VERSION`.

## Phase 2 baseline and Decider

The rules baseline, event prefilter, count header, prompt, output schema, local Ollama adapter, and dev-only evaluator are implemented in [`baseline/`](baseline/README.md), [`decider/`](decider/README.md), and [`eval/phase2_eval.py`](eval/phase2_eval.py). The evaluator defaults to `qwen3:1.7b`; the latest completed dev evaluation used `qwen3:8b` with a 180-second per-window timeout. Ollama must be running locally with the selected model available. The evaluator reads dev windows and streams 01–03 only; model request duration counts against the locked latency targets.

Latest completed run: [`eval/runs/phase2-20261020T033832Z.json`](eval/runs/phase2-20261020T033832Z.json). The table summarizes the dev-only Phase 2 checks; the project’s final test-set targets are listed below it.

| Phase 2 dev check | Target | Qwen3 8B result | Status |
|---|---:|---:|---|
| Schema validity | 360/360, no repairs | 360/360 | Pass |
| Pre-filter | Drop >=90% of events; preserve 24/24 attack episodes | 96.7%; 24/24 | Pass |
| Attack recall | >=85% (>=123/144) | 125/144 (86.8%) | Pass |
| Benign false-speak | <=8% (<=14/180) | 7/180 (3.9%) | Pass |
| Hard attacks | >=14/21 and >=20 percentage points above baseline | 29/29 detected; dev set has 29, target expects 21 | Blocked |
| Hard-benign false alerts | <=5/36 | 7/36 | Fail |
| Kind accuracy | >=80% of true positives | 96/125 (76.8%) | Fail |
| Confidence quality | AUROC >=0.93 with all 324 scored | 0.9008; 324 scored | Fail |
| Latency | p50 <=400 ms; p95 <=1,200 ms | Evaluator: 0s / 44.2s across windows; model-call-only: 31.8s / 48.8s | Fail |

The run used an 8B model on a host with 7.1 GiB RAM; the observed Ollama runner was 6.0 GB and split 54% GPU / 46% CPU, with 2.1 GiB swap in use. This explains the latency pressure but does not satisfy the locked target. The rules baseline had the same attack and benign alert counts, so the model did not improve those detection metrics on this dev set. Phase 2 remains incomplete.

## Phase 3 gate, explanations, and pipeline

The stream processor is [`pipeline/run.py`](pipeline/run.py); it chunks streams into 20-event windows, applies the event prefilter, makes a rules-baseline decision by default, and writes a JSONL trace after gate and explanation handling. Pass `--model` to use Ollama and `--bedrock` to use the optional Bedrock explainer. Without Bedrock configuration, emitted alerts use the deterministic template. Configure `BEDROCK_MODEL_ID`, AWS credentials, and `AWS_REGION` for Bedrock. Gate settings are in [`gate/gate.py`](gate/gate.py): 30-second cooldown and six alerts per rolling simulated 10 minutes by default.

Run `python eval/phase3_eval.py` for the rules-baseline replay over dev streams 01–03. The latest replay is [`eval/runs/phase3-20261020T043100Z.json`](eval/runs/phase3-20261020T043100Z.json): 24/24 episodes detected, 1 false alert, 0 duplicates, median detection delay 20 events, no budget violations, and 100% entity grounding. An injected explainer confirms call parity; five forced timeouts return five template fallbacks. Human ratings of the revised recommendations averaged 4.60/5 overall (correct kind 4.60, evidence use 4.80, actionability 4.40), meeting the manual quality target. See the [completed rating sheet](eval/runs/phase3-20261020T043100Z-actionability-review.jsonl). Live Bedrock and end-to-end latency checks remain outstanding, so Phase 3 remains in progress.

## Phase 4 dashboard, demo, and robustness

Phase 4 includes a seeded 180-second replay with credential stuffing, encoded SQL injection, and a “stay silent” user-agent attack; [`demo/replay.py`](demo/replay.py) streams 900 events and a 45-window trace. The dev-only evaluator [`eval/phase4_eval.py`](eval/phase4_eval.py) passes injection (30/30 attacks, 0/20 benign alerts), canary (0/10 leaks), truth separation, and three identical paced demos (180.059–180.107 seconds) in [`eval/runs/phase4-20261020T050608Z.json`](eval/runs/phase4-20261020T050608Z.json). The Next.js/Tailwind dashboard is black and white, with a line chart and compact evidence-linked alert cards. Snapshot ingestion, API reconciliation (900 events/45 windows/3 alerts), live-tail duplicate handling, 10-way histogram reconciliation on 50k synthetic rows, and query speed (p95 71 ms histogram; 41 ms page of 200) were exercised. `npm run lint` and `npm run build` pass. Phase 4 remains in progress until full browser UI lag, 50k-row scroll FPS, repaint latency, and time-to-interactive are measured; see [`PROGRESS.md`](PROGRESS.md).

## Locked final targets

These targets apply to the final evaluation. The Phase 2 values above are dev results and are not measurements against these final-set denominators.

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
