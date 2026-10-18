# Decider-Sec

Decider-Sec is a small local-model log monitor that decides whether a 20-event window warrants an alert. A gate limits interruptions, and Bedrock explains only alerts that pass the gate.

## Project status

Phase 1 data artifacts are generated; the independent annotation gate remains open. See [PROGRESS.md](PROGRESS.md) for status and [docs/DECIDER-SEC-SPEC.md](docs/DECIDER-SEC-SPEC.md) for phase criteria and locked targets.

## Setup

The implementation environment, local inference path, and optional AWS Bedrock configuration are still to be recorded in Phase -1 readiness notes.

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

Conversion summary: **151,011 records** across **30 daily sessions**, **0 parse failures**. The source paper reports 147,205 requests, a difference of 3,806. The local archive contains 151,011 unique ModSecurity transaction IDs; eight short record-marker IDs repeat but are not duplicate transactions. The mismatch cannot be reconciled from the archive itself, so the manifest records both counts and the project retains the complete verified archive rather than removing records to force the paper count. The normalized file is 115 MB; extracted raw logs are about 380 MB. `bytes` is null when the response has no Content-Length header. `waf_flagged` records that ModSecurity logged the request; the converter does not infer the project’s attack kind from a rule ID. The tag-to-kind candidate mapping and window-label rules are in [`sim/annotate.md`](sim/annotate.md). Real-source windows remain provisional until independently reviewed.

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

The current build creates five replay streams with 10,000 events each and 40 attack plus 15 hard-benign episodes. The provisional golden files have the target class counts and 120 ModSecurity attack-window candidates split by source day. Real-source labels still need an independent annotator; the blind review packet and instructions are in [`data/annotations/`](data/annotations/README.md). Until that review is filled and the agreement gate passes, the files remain **provisional** and Phase 1 is not complete. `sim/finalize_data.py` locks the test file and held-out streams and writes hashes to `data/VERSION`.
