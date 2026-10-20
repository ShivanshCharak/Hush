# Dataset provenance

## ModSecurity real-traffic source

The project uses the public **A Thirty-Day Dataset of Malicious HTTP Requests Blocked by OWASP ModSecurity on a Production Web Server** as its real-world HTTP attack-log source. The source paper reports 147,205 requests over 30 days; entries are anonymized ModSecurity audit logs of requests that triggered OWASP Core Rule Set rules. The dataset includes SQL injection, XSS, file-inclusion, scanner, and malformed/evasive request examples. It is request-level WAF log data, not a complete benign-plus-attack stream.

- **Downloaded archive:** [`sim/capture/external/modsecurity-zenodo-17178461/owasp.zip`](../sim/capture/external/modsecurity-zenodo-17178461/owasp.zip)
- **Zenodo record:** [10.5281/zenodo.17178461](https://zenodo.org/records/17178461)
- **Dataset paper:** [Lucz & Forstner, *Data* 10(11), 186 (2025)](https://doi.org/10.3390/data10110186)
- **License:** Creative Commons Attribution 4.0 International (CC BY 4.0), as stated by the paper. Cite the dataset and paper when reusing it.
- **Archive verification:** Zenodo MD5 `95b7a8237abc163d8ca31e49f7318efd`; local SHA-256 `3c4c976f58cd2da61a543a237ede770529ceee59cdb09295a5998d420a8b30b8`.

The archive was extracted to `sim/capture/external/modsecurity-zenodo-17178461/raw/` and converted to project-shaped web events by [`sim/convert_modsecurity.py`](../sim/convert_modsecurity.py). The converter writes `data/external/modsecurity_events.jsonl`, a manifest with source/output hashes and per-session counts, and an errors file. The converted set contains 151,011 records across 30 daily sessions, with 0 parse failures. The local archive contains 151,011 unique ModSecurity transaction IDs; eight short record-marker IDs repeat but are not duplicate transactions. The difference from the paper's reported 147,205 requests cannot be reconciled from the archive, so the complete verified archive is retained. The normalized file is 115 MB; extracted raw logs are about 380 MB. `bytes` is null when the response has no Content-Length header. `waf_flagged` records that ModSecurity logged the request; the converter does not infer the project's attack kind from a rule ID. The tag-to-kind candidate mapping and window-label rules are in [`sim/annotate.md`](../sim/annotate.md). The owner marked the golden set final after reviewing it; independent human review remains unverified.

## CICIDS2017 auxiliary flow data

Three CICIDS2017 machine-learning CSVs are preserved under [`sim/capture/external/cicids2017/`](../sim/capture/external/cicids2017/README.md). The selected days contain benign traffic, FTP/SSH Patator brute force, and Thursday web brute force/XSS/SQL injection. The official CIC page describes benign background traffic and labeled attacks and links the original dataset paper for citation. The files were fetched from the public [Hugging Face CIC-IDS2017 mirror](https://huggingface.co/datasets/muzom/CIC-IDS2017) because the official download page routes through a download form. Exact per-file row counts and SHA-256 hashes are in the dataset README.

These records add 15,342 brute-force flows and 1,130,178 benign flows, plus 652 XSS and 21 SQL injection flows. They do not provide credential-stuffing or privilege-escalation labels. They are network-flow feature rows, not web/auth log events; this ML CSV variant has no timestamps, source/destination IPs, or HTTP request fields. Keep them separate from `modsecurity_events.jsonl` and do not use them as ordered golden windows. They are auxiliary labeled flow data; using them in the primary windowed log set would require a compatible flow-event schema and sequence source.

- [Official CICIDS2017 description and attack schedule](https://www.unb.ca/cic/datasets/ids-2017.html)
- **Citation:** Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, “Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization,” ICISSP 2018.

## CSIC 2010 inspection

The raw request archive was downloaded and checked. It labels only `Valid`/`Attack`; despite containing login endpoint requests, it has no timestamps or source identities and no labeled brute force, credential stuffing, or privilege escalation. It was removed instead of being added to the project dataset.
