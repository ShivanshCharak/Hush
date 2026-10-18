# CICIDS2017 auxiliary flow records

This directory contains selected raw machine-learning CSVs from CICIDS2017. The original files are preserved byte-for-byte under `raw/`.

## Source and citation

- Official dataset description: https://www.unb.ca/cic/datasets/ids-2017.html
- Public mirror used for the download: https://huggingface.co/datasets/muzom/CIC-IDS2017
- Downloaded: 2026-10-18
- Citation: Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, “Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization,” 4th International Conference on Information Systems Security and Privacy (ICISSP), 2018.
- The official page describes the data as publicly available for researchers and requests citation of the paper. It does not state a specific open-source license. Check the source terms before redistributing the CSVs.

## Included files

| File | Rows | Labels |
|---|---:|---|
| `raw/Monday-WorkingHours.pcap_ISCX.csv` | 529,918 | BENIGN: 529,918 |
| `raw/Tuesday-WorkingHours.pcap_ISCX.csv` | 445,909 | BENIGN: 432,074; FTP-Patator: 7,938; SSH-Patator: 5,897 |
| `raw/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 170,366 | BENIGN: 168,186; Web Attack – Brute Force: 1,507; Web Attack – XSS: 652; Web Attack – Sql Injection: 21 |

Labels were counted from the CSV `Label` column, trimming surrounding whitespace. The Thursday source contains an encoding issue in the attack labels; the raw file is unchanged. `SHA256SUMS` records the hashes of these original files.

Across the included files, there are 15,342 brute-force-labeled rows and 1,130,178 benign rows. There are no labels for credential stuffing or privilege escalation.

## Format limit

These are aggregate network-flow feature rows, not request or authentication events. The selected machine-learning CSV variant has no timestamp, flow ID, source IP, destination IP, HTTP path, request body, or authentication outcome. It cannot be ordered into the project's 20-event web/auth windows or used to infer credentials or privilege changes. Keep it separate from `data/external/modsecurity_events.jsonl`; use only as an auxiliary flow dataset unless the project later defines a compatible flow-event schema and source of sequence metadata.
