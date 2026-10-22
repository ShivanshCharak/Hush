# Detailed results archive

This document preserves detailed locked and development measurements moved from the README. The locked section is based on the saved final artifact; development sections remain explicitly labeled as such.

### Status confound and sensitivity

The 72 ModSecurity-derived dev attack windows contain statuses 301:255, 302:20, 304:37, 400:4, 401:4, 403:373, 404:572, 405:8, 500:32, and 503:135. The 252 simulated windows contain 200:3830, 302:163, 401:859, and 404:188. **Attack recall** means any speak on a labeled attack; **kind accuracy** means the correct kind among spoken attacks; **matching-kind recall** is the secondary count of attacks both spoken and assigned the true kind. Each is reported with a count and denominator. Status-neutral is a sensitivity analysis: for the dev comparison only, status is set to 200 on ModSecurity-marked events.

| Kind | n | Standard speak | Neutral speak | Standard matching-kind | Neutral matching-kind |
|---|---:|---:|---:|---:|---:|
| brute_force | 24 | 24/24 | 24/24 | 24/24 | 24/24 |
| credential_stuffing | 24 | 24/24 | 24/24 | 24/24 | 24/24 |
| path_traversal | 18 | 17/18 | 17/18 | 14/18 | 14/18 |
| priv_esc | 18 | 18/18 | 18/18 | 18/18 | 18/18 |
| scanner_recon | 18 | 12/18 | 10/18 | 12/18 | 10/18 |
| sqli | 24 | 16/24 | 13/24 | 9/24 | 9/24 |
| xss | 18 | 14/18 | 13/18 | 10/18 | 10/18 |
| **Overall** | **144** | **125/144** | **119/144** | **111/144** | **109/144** |

The earlier `125/144 → 109/144` wording incorrectly compared standard speak recall with neutral matching-kind recall. The apples-to-apples comparison is speak recall **125/144 → 119/144**, and matching-kind recall **111/144 → 109/144**. The four web-attack kinds similarly compare speak recall **59/78 → 53/78** and matching-kind recall **45/78 → 43/78**. These seven SQLi attacks were spoken as `scanner_recon` by the automated-probes rule in standard mode:

| SQLi window ID | Detected kind | Rule |
|---|---|---|
| modsec:03-Aug-2025:001200 | scanner_recon | automated probes target sensitive or unrelated endpoints |
| modsec:27-Jul-2025:000520 | scanner_recon | automated probes target sensitive or unrelated endpoints |
| modsec:04-Aug-2025:001160 | scanner_recon | automated probes target sensitive or unrelated endpoints |
| modsec:08-Aug-2025:000400 | scanner_recon | automated probes target sensitive or unrelated endpoints |
| modsec:15-Aug-2025:003380 | scanner_recon | automated probes target sensitive or unrelated endpoints |
| modsec:02-Aug-2025:002240 | scanner_recon | automated probes target sensitive or unrelated endpoints |
| modsec:07-Aug-2025:000400 | scanner_recon | automated probes target sensitive or unrelated endpoints |

Payload-signature rules do not require a 4xx/5xx or WAF-block status. The [shortcut audit](eval/runs/shortcut-audit-dev-20261021.json) AUROC finding remains a separate source-domain warning.

Six dev windows differ in speak outcome or detected kind:

| Window ID | True kind | Standard kind / rule | Neutral kind / rule |
|---|---|---|---|
| modsec:03-Aug-2025:001200 | sqli | scanner_recon / automated probes target sensitive or unrelated endpoints | none / no rule crossed its threshold |
| modsec:29-Jul-2025:000700 | xss | scanner_recon / automated probes target sensitive or unrelated endpoints | none / no rule crossed its threshold |
| modsec:04-Aug-2025:004840 | scanner_recon | scanner_recon / automated probes target sensitive or unrelated endpoints | none / no rule crossed its threshold |
| modsec:15-Aug-2025:003380 | sqli | scanner_recon / automated probes target sensitive or unrelated endpoints | none / no rule crossed its threshold |
| modsec:02-Aug-2025:002240 | sqli | scanner_recon / automated probes target sensitive or unrelated endpoints | none / no rule crossed its threshold |
| modsec:08-Aug-2025:002360 | scanner_recon | scanner_recon / automated probes target sensitive or unrelated endpoints | none / no rule crossed its threshold |

The A–E ablation runner also reports F, a status-neutral sensitivity analysis using the final rules and ModSecurity source markers (code-only). Its dev dry-run covers golden dev windows, dev streams 01–03, evasion v1–v4, and benign-lookalike v1/v2; artifact: [ablation-20261022T043652Z.json](eval/runs/ablation-20261022T043652Z.json). The golden-dev table includes both speak and matching-kind recall.

| Benign lookalike fixture | Before scoped fix | After scoped fix |
|---|---:|---:|
| v1 (in-sample; current rules) | 24/60 false speaks (12 escaped-comment XSS, 12 title traversal) | 0/60 |
| v2 (frozen before scoring; out-of-sample) | not scored before fix | 0/60 |

| Latency gate | Definition | Measured p50 / p95 |
|---|---|---:|
| Handler-to-render | Click handler start through completed render | 242.8 / 288.1 ms |
| Wall | Click action through filtered responses and rendered results | 344 / 394 ms |

Live Bedrock evaluation is pending. The explainer request now sets temperature to 0 explicitly. Run snapshots record the requested Bedrock region `us-west-2`, requested profile ID `us.anthropic.claude-haiku-4-5-20251001-v1:0`, `max_tokens=300`, connect/read timeouts of 4 seconds, and retry `max_attempts=0`; no Bedrock call was made for this update.

## Locked final results and artifact-only analysis

Run artifact: [final-20261022T052438Z.json](eval/runs/final-20261022T052438Z.json). The sections below use that saved artifact and existing preregistration records only. No locked dataset or detector was read for this update. `MISSED` marks failure against an applicable registered target.

### Attempts and precision population

Attempt 1 crashed in the harness with `NameError: name 'legacy_url_only' is not defined`. Attempt 2 crashed because the guard rejected its own counter update: `RuntimeError: locked-run precondition changed after guard`. Neither wrote metrics. Attempt 3 completed and is the only metrics-writing run.

The [decision log](docs/DECIDER-SEC-SPEC.md) defines precision on the scored set, with ambiguous windows excluded (test n=216: 96 attacks and 120 benign). The Phase 5 artifact reports 94 total speaks and 83 spoken attacks in standard mode, and 89 total speaks and 81 spoken attacks in status-neutral mode. That leaves 11 and 8 non-attack speaks, respectively, but the artifact does not divide them into ambiguous versus any other class. Therefore registered scored-set precision cannot be calculated from this artifact. The as-run precision, which uses the harness’s all-speaks denominator, is 83/94 (88.3%) and 81/89 (91.0%).

| Precision population | Standard | Status-neutral |
|---|---:|---:|
| Registered scored set, ambiguous excluded | Not recoverable from saved aggregate; ambiguous speaks not reported | Not recoverable from saved aggregate; ambiguous speaks not reported |
| As run, all counted speaks | MISSED 83/94 (88.3%) | 81/89 (91.0%) |

*Inference, unverified:* Given 0/120 simulated-benign false speaks and a scored set of 96 attacks + 120 benign windows, the 11 standard-mode and 8 status-neutral residual speaks most likely fall among the 24 ambiguous windows. If so, registered precision would be 83/83 and 81/81. The artifact has no per-window data to confirm this; do not treat these inferred values as measured results.

**Post-hoc counts-only confusion matrix:** unavailable. The artifact has no per-window true-kind/predicted-kind pairs or fired-rule fields, so neither the 7×7 counts nor the rules for wrong-kind groups can be recovered without per-window data.

### Benign counts

| Mode | Hard-benign false speaks (n=24; target <=2) | Simulated-benign false speaks (n=120; target <=6) |
|---|---:|---:|
| Standard | 0/24 | 0/120 |
| Status-neutral | 0/24 | 0/120 |

Both modes meet these two false-speak targets. The 11/8 residual non-attack speaks from the precision paragraph are not separated by ambiguity class in the artifact.

### Hard-attack denominator

The registered definition specifies 14 test hard attacks: 20 low-and-slow credential-stuffing cases and 15 encoded-injection cases across the full set; applying the 40% test split gives an expected cohort of 8 low-and-slow stuffing and 6 encoded injection. The Phase 5 metric is 5/6 in both modes, so its recorded denominator is six rather than 14. The final artifact does not preserve hard-flag row counts by type or explain why only six rows entered its measured subset. The 11/14 clause is **not evaluated as registered (evaluator flagged 6 test rows; registered cohort is 8 low-and-slow + 6 encoded)**. The +20-points clause is **MISSED (0 points; baseline A also 5/6)** in both modes.

### Locked-harness limitations

The saved Phase 5 artifact contains aggregate metrics only; it has no per-window predictions or fired-rule names. The post-hoc kind-confusion matrix and precision breakdown therefore cannot be recovered without a second look at locked data. Future harnesses should store per-window outcomes (window IDs, outcome, and fired rule; no event content) so these summaries can be made from the run artifact without another locked-data read.

The locked kind accuracy is 65/83 in standard mode (**MISSED**) and 65/81 status-neutral (**MISSED**). **Dev-only, unverified for test:** the dev rules report had kind accuracy 111/125 (14 wrong-kind speaks); scanner-rule precedence is a hypothesis for those dev errors, not a finding established on the locked set.

### Source-stratified attack recall

| Mode | Source cohort | Kind | n | Speak recall | Matching-kind recall |
|---|---|---|---:|---:|---:|
| Standard | real (ModSecurity-derived) | path_traversal | 12 | 12/12 | 4/12 |
| Standard | real (ModSecurity-derived) | scanner_recon | 12 | 7/12 | 7/12 |
| Standard | real (ModSecurity-derived) | sqli | 16 | 11/16 | 4/16 |
| Standard | real (ModSecurity-derived) | xss | 8 | 5/8 | 2/8 |
| Standard | real (ModSecurity-derived) | **Overall** | **48** | **35/48** | — |
| Standard | simulator-generated | brute_force | 16 | 16/16 | 16/16 |
| Standard | simulator-generated | credential_stuffing | 16 | 16/16 | 16/16 |
| Standard | simulator-generated | priv_esc | 12 | 12/12 | 12/12 |
| Standard | simulator-generated | xss | 4 | 4/4 | 4/4 |
| Standard | simulator-generated | **Overall** | **48** | **48/48** | — |
| Status-neutral | real (ModSecurity-derived) | path_traversal | 12 | 12/12 | 4/12 |
| Status-neutral | real (ModSecurity-derived) | scanner_recon | 12 | 7/12 | 7/12 |
| Status-neutral | real (ModSecurity-derived) | sqli | 16 | 10/16 | 4/16 |
| Status-neutral | real (ModSecurity-derived) | xss | 8 | 4/8 | 2/8 |
| Status-neutral | real (ModSecurity-derived) | **Overall** | **48** | **33/48** | — |
| Status-neutral | simulator-generated | brute_force | 16 | 16/16 | 16/16 |
| Status-neutral | simulator-generated | credential_stuffing | 16 | 16/16 | 16/16 |
| Status-neutral | simulator-generated | priv_esc | 12 | 12/12 | 12/12 |
| Status-neutral | simulator-generated | xss | 4 | 4/4 | 4/4 |
| Status-neutral | simulator-generated | **Overall** | **48** | **48/48** | — |

Brute force, credential stuffing, and privilege escalation are simulator-only in this split; they are not real-world recall estimates.

### A–F ablation

A–E are standard mode; F is status-neutral. E is the final rules variant with template explanations. `MISSED` is shown for E/F where their measured value misses a locked target.

| Variant | Mode | Attack speak recall | As-run precision | Kind accuracy | Matching-kind recall | Sim-benign false speaks | Hard-attack target status | Hard-benign false speaks | Held-out episode recall | False alerts | Duplicates | Median TTD (events) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| A | Standard | 83/96 | 83/98 | 65/83 | 65/96 | 4/120 | 5/6 | 4/24 | 16/16 | 2 | 0/16 | 20.0 |
| B | Standard | 83/96 | 83/98 | 65/83 | 65/96 | 4/120 | 5/6 | 4/24 | 16/16 | 2 | 0/16 | 20.0 |
| C | Standard | 83/96 | 83/98 | 65/83 | 65/96 | 4/120 | 5/6 | 4/24 | 16/16 | 2 | 0/16 | 20.0 |
| D | Standard | 83/96 | 83/94 | 65/83 | 65/96 | 0/120 | 5/6 | 0/24 | 16/16 | 0 | 0/16 | 20.0 |
| E | Standard | MISSED 83/96 | MISSED 83/94 | MISSED 65/83 | 65/96 | 0/120 | 11/14 not evaluated as registered; +20 MISSED (0 points) | 0/24 | 16/16 | 0 | 0/16 | 20.0 |
| F | Status-neutral | MISSED 81/96 | 81/89 | MISSED 65/81 | 65/96 | 0/120 | 11/14 not evaluated as registered; +20 MISSED (0 points) | 0/24 | 16/16 | 0 | 0/16 | 20.0 |

### Held-out streams 04–05

Both held-out streams are simulator-generated. Matching rule: an alert window overlaps a labeled episode when `alert.end >= episode.start_idx` and `alert.start < episode.end_idx`; the earliest overlapping alert end defines detection delay.

| Variant | Stream | Episode recall | False alerts | Duplicates | Median detect events |
|---|---|---:|---:|---:|---:|
| E | stream_04 | 8/8 | 0 | 0 | 20.0 |
| E | stream_05 | 8/8 | 0 | 0 | 20.0 |
| F | stream_04 | 8/8 | 0 | 0 | 20.0 |
| F | stream_05 | 8/8 | 0 | 0 | 20.0 |

E emitted 16 held-out alerts; 8 of 16 emitted alerts were graded. The 8/8 valid evidence IDs and 34/34 grounded entity mentions are on that graded subset. Template explanations are grounded by construction; live Bedrock grounding is pending.

### Evasion fixtures

Rows show attack windows detected / fixture n. A–E are standard; F is status-neutral. No separate pass threshold for each family is registered, so these are descriptive counts.

| Variant | Fixture | Family | Detected / n |
|---|---|---|---:|
| A | v1 | case_comment_obfuscation | 13/20 |
| A | v1 | double_url_encoding | 18/20 |
| A | v1 | slow_rate_5plus_ips | 0/20 |
| A | v2 | parser_obfuscation | 11/20 |
| A | v2 | slow_rate_10ip_30m_rotating_users | 0/20 |
| A | v2 | triple_encoding | 17/20 |
| A | v3 | encoding_html_entity | 7/10 |
| A | v3 | encoding_unicode_escape | 10/10 |
| A | v3 | parser_path_separator_confusion | 10/10 |
| A | v3 | parser_sql_keyword_splitting | 4/10 |
| A | v3 | slow_rate_15m_rotating_usernames_20ip | 0/7 |
| A | v3 | slow_rate_30m_rotating_usernames_20ip | 0/7 |
| A | v3 | slow_rate_45m_rotating_usernames_20ip | 0/6 |
| A | v4 | comment_case_obfuscation | 0/8 |
| A | v4 | html_entity_encoding | 0/8 |
| A | v4 | nested_triple_encoding_3pass | 4/4 |
| A | v4 | nested_triple_encoding_4pass | 0/4 |
| A | v4 | slow_rate_15m_rotating_users_14ip | 0/5 |
| A | v4 | slow_rate_30m_rotating_users_14ip | 0/5 |
| A | v4 | slow_rate_45m_rotating_users_14ip | 0/5 |
| A | v4 | slow_rate_60m_rotating_users_14ip | 0/5 |
| A | v4 | sql_keyword_splitting | 0/8 |
| A | v4 | unicode_escape_encoding | 0/8 |
| B | v1 | case_comment_obfuscation | 13/20 |
| B | v1 | double_url_encoding | 18/20 |
| B | v1 | slow_rate_5plus_ips | 20/20 |
| B | v2 | parser_obfuscation | 11/20 |
| B | v2 | slow_rate_10ip_30m_rotating_users | 0/20 |
| B | v2 | triple_encoding | 17/20 |
| B | v3 | encoding_html_entity | 7/10 |
| B | v3 | encoding_unicode_escape | 10/10 |
| B | v3 | parser_path_separator_confusion | 10/10 |
| B | v3 | parser_sql_keyword_splitting | 4/10 |
| B | v3 | slow_rate_15m_rotating_usernames_20ip | 7/7 |
| B | v3 | slow_rate_30m_rotating_usernames_20ip | 0/7 |
| B | v3 | slow_rate_45m_rotating_usernames_20ip | 0/6 |
| B | v4 | comment_case_obfuscation | 0/8 |
| B | v4 | html_entity_encoding | 0/8 |
| B | v4 | nested_triple_encoding_3pass | 4/4 |
| B | v4 | nested_triple_encoding_4pass | 0/4 |
| B | v4 | slow_rate_15m_rotating_users_14ip | 5/5 |
| B | v4 | slow_rate_30m_rotating_users_14ip | 0/5 |
| B | v4 | slow_rate_45m_rotating_users_14ip | 0/5 |
| B | v4 | slow_rate_60m_rotating_users_14ip | 0/5 |
| B | v4 | sql_keyword_splitting | 0/8 |
| B | v4 | unicode_escape_encoding | 0/8 |
| C | v1 | case_comment_obfuscation | 13/20 |
| C | v1 | double_url_encoding | 18/20 |
| C | v1 | slow_rate_5plus_ips | 20/20 |
| C | v2 | parser_obfuscation | 20/20 |
| C | v2 | slow_rate_10ip_30m_rotating_users | 0/20 |
| C | v2 | triple_encoding | 17/20 |
| C | v3 | encoding_html_entity | 10/10 |
| C | v3 | encoding_unicode_escape | 10/10 |
| C | v3 | parser_path_separator_confusion | 10/10 |
| C | v3 | parser_sql_keyword_splitting | 10/10 |
| C | v3 | slow_rate_15m_rotating_usernames_20ip | 7/7 |
| C | v3 | slow_rate_30m_rotating_usernames_20ip | 0/7 |
| C | v3 | slow_rate_45m_rotating_usernames_20ip | 0/6 |
| C | v4 | comment_case_obfuscation | 8/8 |
| C | v4 | html_entity_encoding | 8/8 |
| C | v4 | nested_triple_encoding_3pass | 4/4 |
| C | v4 | nested_triple_encoding_4pass | 0/4 |
| C | v4 | slow_rate_15m_rotating_users_14ip | 5/5 |
| C | v4 | slow_rate_30m_rotating_users_14ip | 0/5 |
| C | v4 | slow_rate_45m_rotating_users_14ip | 0/5 |
| C | v4 | slow_rate_60m_rotating_users_14ip | 0/5 |
| C | v4 | sql_keyword_splitting | 8/8 |
| C | v4 | unicode_escape_encoding | 8/8 |
| D | v1 | case_comment_obfuscation | 13/20 |
| D | v1 | double_url_encoding | 18/20 |
| D | v1 | slow_rate_5plus_ips | 20/20 |
| D | v2 | parser_obfuscation | 20/20 |
| D | v2 | slow_rate_10ip_30m_rotating_users | 0/20 |
| D | v2 | triple_encoding | 17/20 |
| D | v3 | encoding_html_entity | 10/10 |
| D | v3 | encoding_unicode_escape | 10/10 |
| D | v3 | parser_path_separator_confusion | 10/10 |
| D | v3 | parser_sql_keyword_splitting | 10/10 |
| D | v3 | slow_rate_15m_rotating_usernames_20ip | 7/7 |
| D | v3 | slow_rate_30m_rotating_usernames_20ip | 0/7 |
| D | v3 | slow_rate_45m_rotating_usernames_20ip | 0/6 |
| D | v4 | comment_case_obfuscation | 8/8 |
| D | v4 | html_entity_encoding | 8/8 |
| D | v4 | nested_triple_encoding_3pass | 4/4 |
| D | v4 | nested_triple_encoding_4pass | 0/4 |
| D | v4 | slow_rate_15m_rotating_users_14ip | 5/5 |
| D | v4 | slow_rate_30m_rotating_users_14ip | 0/5 |
| D | v4 | slow_rate_45m_rotating_users_14ip | 0/5 |
| D | v4 | slow_rate_60m_rotating_users_14ip | 0/5 |
| D | v4 | sql_keyword_splitting | 8/8 |
| D | v4 | unicode_escape_encoding | 8/8 |
| E | v1 | case_comment_obfuscation | 13/20 |
| E | v1 | double_url_encoding | 18/20 |
| E | v1 | slow_rate_5plus_ips | 20/20 |
| E | v2 | parser_obfuscation | 20/20 |
| E | v2 | slow_rate_10ip_30m_rotating_users | 0/20 |
| E | v2 | triple_encoding | 17/20 |
| E | v3 | encoding_html_entity | 10/10 |
| E | v3 | encoding_unicode_escape | 10/10 |
| E | v3 | parser_path_separator_confusion | 10/10 |
| E | v3 | parser_sql_keyword_splitting | 10/10 |
| E | v3 | slow_rate_15m_rotating_usernames_20ip | 7/7 |
| E | v3 | slow_rate_30m_rotating_usernames_20ip | 0/7 |
| E | v3 | slow_rate_45m_rotating_usernames_20ip | 0/6 |
| E | v4 | comment_case_obfuscation | 8/8 |
| E | v4 | html_entity_encoding | 8/8 |
| E | v4 | nested_triple_encoding_3pass | 4/4 |
| E | v4 | nested_triple_encoding_4pass | 0/4 |
| E | v4 | slow_rate_15m_rotating_users_14ip | 5/5 |
| E | v4 | slow_rate_30m_rotating_users_14ip | 0/5 |
| E | v4 | slow_rate_45m_rotating_users_14ip | 0/5 |
| E | v4 | slow_rate_60m_rotating_users_14ip | 0/5 |
| E | v4 | sql_keyword_splitting | 8/8 |
| E | v4 | unicode_escape_encoding | 8/8 |
| F | v1 | case_comment_obfuscation | 13/20 |
| F | v1 | double_url_encoding | 18/20 |
| F | v1 | slow_rate_5plus_ips | 20/20 |
| F | v2 | parser_obfuscation | 20/20 |
| F | v2 | slow_rate_10ip_30m_rotating_users | 0/20 |
| F | v2 | triple_encoding | 17/20 |
| F | v3 | encoding_html_entity | 10/10 |
| F | v3 | encoding_unicode_escape | 10/10 |
| F | v3 | parser_path_separator_confusion | 10/10 |
| F | v3 | parser_sql_keyword_splitting | 10/10 |
| F | v3 | slow_rate_15m_rotating_usernames_20ip | 7/7 |
| F | v3 | slow_rate_30m_rotating_usernames_20ip | 0/7 |
| F | v3 | slow_rate_45m_rotating_usernames_20ip | 0/6 |
| F | v4 | comment_case_obfuscation | 8/8 |
| F | v4 | html_entity_encoding | 8/8 |
| F | v4 | nested_triple_encoding_3pass | 4/4 |
| F | v4 | nested_triple_encoding_4pass | 0/4 |
| F | v4 | slow_rate_15m_rotating_users_14ip | 5/5 |
| F | v4 | slow_rate_30m_rotating_users_14ip | 0/5 |
| F | v4 | slow_rate_45m_rotating_users_14ip | 0/5 |
| F | v4 | slow_rate_60m_rotating_users_14ip | 0/5 |
| F | v4 | sql_keyword_splitting | 8/8 |
| F | v4 | unicode_escape_encoding | 8/8 |

### Benign lookalike fixtures

Rows show false speaks / fixture n. A–E are standard; F is status-neutral. No separate pass threshold for each category is registered, so these are descriptive counts.

| Variant | Fixture | Category | False speaks / n |
|---|---|---|---:|
| A | v1 | apostrophes_in_names | 0/12 |
| A | v1 | html_tags_in_comment_text | 0/12 |
| A | v1 | long_encoded_parameters | 0/12 |
| A | v1 | sql_keywords_in_search | 0/12 |
| A | v1 | traversal_looking_document_titles | 12/12 |
| A | v2 | apostrophes_in_names | 0/12 |
| A | v2 | html_tags_in_comment_text | 0/12 |
| A | v2 | long_encoded_parameters | 0/12 |
| A | v2 | sql_keywords_in_search | 0/12 |
| A | v2 | traversal_looking_document_titles | 12/12 |
| B | v1 | apostrophes_in_names | 0/12 |
| B | v1 | html_tags_in_comment_text | 0/12 |
| B | v1 | long_encoded_parameters | 0/12 |
| B | v1 | sql_keywords_in_search | 0/12 |
| B | v1 | traversal_looking_document_titles | 0/12 |
| B | v2 | apostrophes_in_names | 0/12 |
| B | v2 | html_tags_in_comment_text | 0/12 |
| B | v2 | long_encoded_parameters | 0/12 |
| B | v2 | sql_keywords_in_search | 0/12 |
| B | v2 | traversal_looking_document_titles | 0/12 |
| C | v1 | apostrophes_in_names | 0/12 |
| C | v1 | html_tags_in_comment_text | 0/12 |
| C | v1 | long_encoded_parameters | 0/12 |
| C | v1 | sql_keywords_in_search | 0/12 |
| C | v1 | traversal_looking_document_titles | 0/12 |
| C | v2 | apostrophes_in_names | 0/12 |
| C | v2 | html_tags_in_comment_text | 0/12 |
| C | v2 | long_encoded_parameters | 0/12 |
| C | v2 | sql_keywords_in_search | 0/12 |
| C | v2 | traversal_looking_document_titles | 0/12 |
| D | v1 | apostrophes_in_names | 0/12 |
| D | v1 | html_tags_in_comment_text | 0/12 |
| D | v1 | long_encoded_parameters | 0/12 |
| D | v1 | sql_keywords_in_search | 0/12 |
| D | v1 | traversal_looking_document_titles | 0/12 |
| D | v2 | apostrophes_in_names | 0/12 |
| D | v2 | html_tags_in_comment_text | 0/12 |
| D | v2 | long_encoded_parameters | 0/12 |
| D | v2 | sql_keywords_in_search | 0/12 |
| D | v2 | traversal_looking_document_titles | 0/12 |
| E | v1 | apostrophes_in_names | 0/12 |
| E | v1 | html_tags_in_comment_text | 0/12 |
| E | v1 | long_encoded_parameters | 0/12 |
| E | v1 | sql_keywords_in_search | 0/12 |
| E | v1 | traversal_looking_document_titles | 0/12 |
| E | v2 | apostrophes_in_names | 0/12 |
| E | v2 | html_tags_in_comment_text | 0/12 |
| E | v2 | long_encoded_parameters | 0/12 |
| E | v2 | sql_keywords_in_search | 0/12 |
| E | v2 | traversal_looking_document_titles | 0/12 |
| F | v1 | apostrophes_in_names | 0/12 |
| F | v1 | html_tags_in_comment_text | 0/12 |
| F | v1 | long_encoded_parameters | 0/12 |
| F | v1 | sql_keywords_in_search | 0/12 |
| F | v1 | traversal_looking_document_titles | 0/12 |
| F | v2 | apostrophes_in_names | 0/12 |
| F | v2 | html_tags_in_comment_text | 0/12 |
| F | v2 | long_encoded_parameters | 0/12 |
| F | v2 | sql_keywords_in_search | 0/12 |
| F | v2 | traversal_looking_document_titles | 0/12 |

### Remaining evaluation status

Bedrock metrics: pending; the locked run used the template explainer and made no Bedrock call. Injection robustness and decision latency were not part of this locked run.

### Recall by data source (dev)

The golden-set count manifest gives 144 dev and 96 test attack windows (240 total). The ModSecurity selection manifest declares 72 real windows in dev and 48 in test; the rest are simulator-generated. These source counts are derived from manifest counts and declared per-kind selection quotas, without reading test or held-out window contents. Recall below is the current dev rules result; for mixed-source XSS it is not split by provenance.

| Kind / source family | Dev ModSecurity | Dev simulated | Test ModSecurity | Test simulated | Dev recall |
|---|---:|---:|---:|---:|---:|
| sqli (real-traffic family) | 24 | 0 | 16 | 0 | 16/24 |
| xss (real-traffic family; mixed; source-specific recall unavailable) | 12 | 6 | 8 | 4 | 14/18 overall |
| path_traversal (real-traffic family) | 18 | 0 | 12 | 0 | 17/18 |
| scanner_recon (real-traffic family) | 18 | 0 | 12 | 0 | 12/18 |
| brute_force (simulated only) | 0 | 24 | 0 | 16 | 24/24 |
| credential_stuffing (simulated only) | 0 | 24 | 0 | 16 | 24/24 |
| priv_esc (simulated only) | 0 | 18 | 0 | 12 | 18/18 |
| **Total** | **72** | **72** | **48** | **48** | **125/144** |

Brute force, credential stuffing, and privilege escalation are **100% simulated** in both splits. Simulated-kind recall is not a real-world estimate: the simulator and rules were co-developed. The perfect/near-perfect simulated-kind results should not be generalized to production traffic.

**Known confound:** the dev-only non-content shortcut audit ([report](eval/runs/shortcut-audit-dev-20261021.json)) trained L2 logistic regression to distinguish ModSecurity attack windows from simulated benign windows using coarse user-agent family, status distribution, field-presence rates, byte-null rate, and timing/within-window metadata. Five-fold stratified CV pooled AUROC was **1.000** (folds 1.000 each; 72 real attacks, 180 simulated benign). The top five permutation drops were `status_4xx` (0.002593 AUROC), `presence_username` (0.000741), then `event_count`, `bytes_null_rate`, and `unique_source_ips` (each 0.000000). Removing the top 1 feature left AUROC **1.000**; removing the top 3 yielded **0.9977**; removing the top 5 yielded **0.9978**. The remaining metadata still separates source domains nearly perfectly; this is a source shortcut warning, not evidence of detector quality. The audit did not change data or rules.



### Model comparison

| Model and scope | Attack recall (real / simulated) | Hard-benign false speaks vs simulated benign traffic | Normal-benign false speaks vs simulated benign traffic | Kind accuracy | AUROC (model-called only) | Total latency p50 / p95 |
|---|---:|---:|---:|---:|---:|---:|
| [Rules baseline, shared 60-window sample](eval/runs/phase2-requested-qwen3-8b-sample60.json) | 21/24 (source split not recorded) | 3/6 | 0/24 | 18/21 | not run | not run |
| [Rules baseline, full dev](eval/runs/phase2-20261020T033832Z.json) (kind comparison: [audit](eval/runs/phase2-followup-audit-20261020T095052Z.json)) | 125/144 (source split not recorded) | 7/36 | 0/144 | 111/125 | not run | not run |
| [Current rules pipeline](eval/runs/dev-rules-20261021T055255Z.json) | 53/72 real; 72/72 simulated (125/144 overall) | 0/36 | 0/144 | 111/125 | not applicable | not applicable |
| Current Bedrock explainer (no run) | — | — | — | rules-owned | pending | pending |
| [qwen3:1.7b, 354 dev windows](eval/runs/phase2-requested-qwen3-1.7b.json) | 46/141 | 3/34 | 23/143 | 42/46 | 0.497 (n=314) | 6.22 / 10.14 s |
| [qwen3:4b, shared 60-window sample](eval/runs/phase2-requested-qwen3-4b-sample60.json) | 13/24 | 2/6 | 0/24 | 9/13 | 0.909 (n=52) | 13.59 / 32.60 s |
| [qwen3:8b, shared 60-window sample](eval/runs/phase2-requested-qwen3-8b-sample60.json) | 22/24 | 3/6 | 1/24 | 15/22 | 0.976 (n=54) | 30.89 / 67.46 s |

The shared-sample rules figures were computed deterministically on the exact window IDs in the 8B sample artifact, using the existing dev windows; no model calls were made.

On the shared sample, the rules recalled 21/24 and 8B recalled 22/24, a one-window difference; no recall advantage is claimed.

### Evasion v1-v4 (dev mutations)

| Evasion-v1 family | Before normalization | Current rules | qwen3:1.7b historical |
|---|---:|---:|---:|
| Double URL encoding | 18/20 | 18/20 | 8/20 |
| Case/comment obfuscation | 13/20 | 13/20 | 3/20 |
| Slow-rate across 5+ IPs | 20/20 | 20/20 | 0/20 |

Historical model values are from [the Evasion-v1 model run](eval/runs/evasion-qwen3-1.7b.json). Final post-normalization numbers are from the latest rules artifact; earlier intermediate normalization scoring reached 20/20 on case/comment, but the final comment-handling revision regressed to 13/20.

| Mutation family | Evasion-v2 pre-fix | Evasion-v2 post-fix, in-sample | Evasion-v3 pre-fix | Evasion-v3 post-fix, in-sample | Evasion-v4 current |
|---|---:|---:|---:|---:|---:|
| Slow, 15m spacing | — | — | 7/7 | 7/7 | 5/5 |
| Slow, 30m spacing | 0/20 | 0/20 | 0/7 | 0/7 | 0/5 |
| Slow, 45m spacing | — | — | 0/6 | 0/6 | 0/5 |
| Slow, 60m spacing | — | — | — | — | 0/5 |
| Triple / nested encoding (3 passes) | 17/20 | 17/20 | — | — | 4/4 |
| Nested encoding (4 passes) | — | — | — | — | 0/4 |
| HTML entities | — | — | 7/10 | 10/10 | 8/8 |
| Unicode escapes | — | — | 10/10 | 10/10 | 8/8 |
| Parser obfuscation / SQL splitting | 11/20 | 20/20 | 4/10 | 10/10 | 8/8 |
| Path separator confusion | — | — | 10/10 | 10/10 | — |
| Comment/case obfuscation | — | — | — | — | 8/8 |

Evasion-v2 pre-fix figures are preserved from [`dev-rules-20261020T181310Z.json`](eval/runs/dev-rules-20261020T181310Z.json). V1-v3 are the original frozen mutation sets; the clean v4 revision is [`evasion-v4-clean-dev.json`](eval/runs/evasion-v4-clean-dev.json), committed before rescoring. The first v4 candidate was contaminated by unchanged source payloads, so its per-family payload scores are invalid and remain documented in the run report. V4 covers 60 new dev mutations; its 3-pass nested cases pass while the intentionally deeper 4-pass cases do not.

V4 current recall totals **41/60**. V2/v3 post-fix figures are in-sample because those same development mutation families informed the rule and normalizer changes; they are not held-out estimates. The clean v4 fixture was built after the first v4 scoring exposed contamination, then committed before its own detector scoring.

Evasion-v4 was frozen before any detector run (candidate commit `e4756fdb`; clean, uncontaminated revision commit `89b5d1d7`). V1-v3 pre-fix references are retained in the current rules run. Normalization is capped at three repeated URL-decode passes, then decodes HTML and Unicode escapes, strips SQL comments, and collapses whitespace.

### Dashboard measurements (dev)

- Dashboard desktop Lighthouse with a healthy API: LCP 733 ms, TBT 3 ms, JS transfer 243,713 bytes (263,881 bytes total). The dashboard remains under the 300 KB JS-transfer target. The 55 FPS scroll gate was missed: on headed Chrome with the AMD Radeon Graphics GPU, the 50k-row virtualized table sustained 40.0 FPS average with p95 frame interval 50 ms; one 69 ms long task fell in the 2.5-second scroll sample. The table had 20 rows initially and 19 after scroll. Fixed 42px row sizing, overscan reduced from 12 to 6, and CSS layout/paint containment are in place. Practical target deviation: >=40 FPS average, p95 frame interval <=50 ms, and at most one >50 ms long task in a 2.5-second sample. For the real local FastAPI API populated from dev stream 01, filter latency is defined as click-handler-start to render-complete for handler-to-render, and click action to both filtered responses and rendered results for wall time. The earlier `kind=sqli` sample was 282.7 ms handler-to-render versus 351 ms wall time (handler 2.4 ms, scheduling 45.4 ms, network 81 ms, render 153.9 ms). A separate 20-click profile used 20 distinct `src_ip` filters and nearest-rank p50/p95: handler-to-render 242.8/288.1 ms and wall 344/394 ms. The profile is [here](eval/runs/dashboard-real-api-filter-20-20261022T040747Z.json). No explicit debounce was present in the filter code. Filter actions requested event and histogram routes only; the initial page load also requested alerts. The filter profile did not navigate away from the page. Alert-card-to-evidence linkage passed in the 50k-row browser fixture. The separate synthetic filter portion of the scroll profile measured 694 ms repaint and is not the real-API timing.

### Additional development findings

### What we found

- The exact per-source brute-force rule is at least five failed logins for the same username and source IP in a rolling 60 seconds, with no successful login for that username in the interval. The distributed rule is at least three distinct source IPs failing for the same username in a trailing 60 minutes, with no success for that username in that interval. Both apply; labels do not authorize sources.
- Current rules dev metrics are 125/144 attack recall (53/72 ModSecurity, 72/72 simulated), 111/125 kind accuracy, 0/36 hard-benign false speaks vs simulated benign traffic, and 0/144 normal-benign false speaks vs simulated benign traffic. Per-kind: brute force 24/24, credential stuffing 24/24, SQLi 16/24, XSS 14/18, path traversal 17/18, privilege escalation 18/18, scanner reconnaissance 12/18. Dev streams 01-03 had 0 false alerts each.
- Source-stratified dev recall is 53/72 on ModSecurity attacks and 72/72 on simulated attacks (125/144 overall). See [Recall by data source](#recall-by-data-source-dev); simulated-kind results are not a real-world estimate.
- Brute force exact rule: >=5 failures for the same username from one source IP in a rolling 60 seconds, with no matching success in that interval. Distributed brute force: same username fails from >=3 distinct IPs within 60 minutes and has no success in that interval. A separate auth-endpoint stuffing rule uses >=4 distinct failed usernames, >=2 distinct IPs, >=4 failures, and successes/attempts <=0.25 in 60 minutes. Thresholds were proposed using dev streams 01-03 only.
- With rotating usernames, the distinct-username stuffing rule catches v4 at 15-minute spacing (5/5; five failures fit within 60 minutes) but misses 30/45/60-minute spacing because those sequences contribute only three or fewer failures in the trailing hour. V2 30-minute slow rate remains 0/20; v3 remains 0/7 at 30m and 0/6 at 45m. The 60-minute change does not solve this attack shape.
- The final comment-normalization tweak restored SQL-split evasion recall (v3 4/10 to 10/10; v2 parser 11/20 to 20/20), but v1 case/comment ended at 13/20 after an intermediate 20/20. This regression is retained as a known result for follow-up.
- Reviewer value did not separate attacks from benign controls: all 24 emitted dev-stream attack alerts were confirmed and all 7 formerly false-speaking hard-benign windows (with allowlist flag removed) were also confirmed; contested rate was 0% for each. The confirmed/contested badge and trace field were removed. The model can supply explanation hints only and cannot suppress or create alerts.
- Dashboard desktop Lighthouse with a healthy API: LCP 733 ms, TBT 3 ms, JS transfer 243,713 bytes (263,881 bytes total). The dashboard remains under the 300 KB JS-transfer target. The 55 FPS scroll gate was missed: on headed Chrome with the AMD Radeon Graphics GPU, the 50k-row virtualized table sustained 40.0 FPS average with p95 frame interval 50 ms; one 69 ms long task fell in the 2.5-second scroll sample. The table had 20 rows initially and 19 after scroll. Fixed 42px row sizing, overscan reduced from 12 to 6, and CSS layout/paint containment are in place. Practical target deviation: >=40 FPS average, p95 frame interval <=50 ms, and at most one >50 ms long task in a 2.5-second sample. For the real local FastAPI API populated from dev stream 01, filter latency is defined as click-handler-start to render-complete for handler-to-render, and click action to both filtered responses and rendered results for wall time. The earlier `kind=sqli` sample was 282.7 ms handler-to-render versus 351 ms wall time (handler 2.4 ms, scheduling 45.4 ms, network 81 ms, render 153.9 ms). A separate 20-click profile used 20 distinct `src_ip` filters and nearest-rank p50/p95: handler-to-render 242.8/288.1 ms and wall 344/394 ms. The profile is [here](eval/runs/dashboard-real-api-filter-20-20261022T040747Z.json). No explicit debounce was present in the filter code. Filter actions requested event and histogram routes only; the initial page load also requested alerts. The filter profile did not navigate away from the page. Alert-card-to-evidence linkage passed in the 50k-row browser fixture. The separate synthetic filter portion of the scroll profile measured 694 ms repaint and is not the real-API timing.
- A–E ablation dry run on the same dev streams 01–03 (24 attacks, 9 hard-benign episodes): all variants detected 24/24 attacks. A (frozen naive rules), B (+cross-IP/stuffing), and C (+normalization) each emitted 1 hard-benign false alert (25 alerts); D (+allowlist) and E (+template explanation proxy; Bedrock pending) emitted 0 hard-benign false alerts (24 alerts). E made zero Bedrock calls. This small in-sample subset contains no attacks that distinguish A/B/C, so equal recall does not show those additions have no value on other data.
- Frozen [benign-lookalike-v1](eval/fixtures/benign-lookalike-v1.jsonl) pre-fix false speaks by category (12 each): A naive frozen rules = 12/60 overall (search 0/12, apostrophes 0/12, escaped HTML comments 0/12, path-like titles 12/12, long encoded parameters 0/12); B + cross-IP/stuffing = the same; C + normalization = 24/60 (escaped HTML 12/12 and path-like titles 12/12); D + allowlist = 24/60; E + explanation-only template proxy = 24/60. V1 was committed as `ec0c7fe2` before scoring (SHA-256 `d17178bc03daf13e8f71d5c1c2202b4c1ae4660b5303ee571b86a1db81cfc120`); full pre-fix A–E counts are in [the original ablation run](eval/runs/ablation-20261021T064132Z.json). The 24 pre-fix current-rule false speaks were IDs lookalike-v1-025–036 (rule `xss`) and lookalike-v1-037–048 (rule `path_traversal`), each with reason “request payload matches an attack signature.”
- The two scoped exceptions were applied after v2 was frozen and committed. The current D/E rules now false-speak on 0/60 v1 windows (in-sample after fix) and 0/60 v2 windows (out-of-sample), with 0/12 in each of the five categories in each set. The frozen naive A comparator remains at 12/60, all path-like titles; it is not the modified current rules. The fix passed the dev acceptance values unchanged: attack recall 125/144, kind accuracy 111/125, hard-benign false speaks 0/36, normal-benign false speaks 0/144, and dev-stream false alerts 0. Clean evasion-v4 recall is 41/60, above the 39/60 gate. The before/after reports are [the v1/v2 ablation](eval/runs/ablation-20261022T035934Z.json) and [the dev rules evaluation](eval/runs/dev-rules-20261022T035933Z.json).
- The earlier status-neutralization audit retains status-code counts and its original scanner-recon review in [the dev audit](eval/runs/dev-status-lookalike-audit-20261022.json). The apples-to-apples standard/neutral metrics and all changed dev attack windows are in the newer [status-sensitivity ablation artifact](eval/runs/ablation-20261022T043652Z.json).
- Known detector limitations: rotating-username slow-rate attacks at spacing >=30 minutes remain mostly undetected; nested encoding requiring 4 or more decode passes exceeds the 3-pass normalizer; each dev stream spans only about 33 minutes, so these streams cannot validate long observation windows such as 60 minutes.

- On the 1.7B 354-window run, recall was 46/141 versus the rules baseline's 125/144 on the full dev set; it caught 0/19 attacks the rules missed. The scopes differ, so the recall figures are not a paired comparison.
- Qwen3 4B was weak on the shared sample at 13/24, below the rules baseline's 21/24.
- Qwen3 8B had the strongest model-called confidence signal on the shared sample (AUROC 0.976, n=54), but total latency was 30.89/67.46 s p50/p95. On the earlier full-dev run, model and rules both recalled 125/144.
- On the earlier full-dev 8B artifact, rules kind accuracy was 111/125 and model kind accuracy was 96/125. The shared sample also has lower model kind accuracy than rules (18/21 for rules versus 9/13 for 4B and 15/22 for 8B); on the 1.7B scope, rules were 108/122 and the model 42/46. These are conditional on each detector's speaks, so the claim that every model is worse on kind accuracy is not supported across all scopes.
- Prompt processing dominated the 4B sample p50 latency (12.45 s prompt evaluation versus 1.10 s generation). The earlier 8B run was rules-gated: the model's speak decisions matched the rules because 200 no-candidate windows were skipped and every one of 160 candidate windows was sent to the model.

**Hardware:** historical Ollama study ran with 7.1 GiB host RAM, 6.0 GB runner, and 54% GPU / 46% CPU; physical GPU model was not recorded. The current headed Chrome run records its detected WebGL renderer and hardware-acceleration status in the Playwright artifact.

<details>
<summary>Earlier 8B run (rules-gated, context 8192, superseded)</summary>

Earlier completed run: [phase2-20261020T033832Z.json](eval/runs/phase2-20261020T033832Z.json).

| Phase 2 dev check | Target | Qwen3 8B result | Status |
|---|---:|---:|---|
| Schema validity | 360/360, no repairs | 360/360 | Pass |
| Pre-filter | Drop >=90% of events; preserve 24/24 attack episodes | 96.7%; 24/24 | Pass |
| Attack recall | >=85% (>=123/144) | 125/144 (86.8%) | Pass |
| Benign false-speak vs simulated benign traffic | <=8% (<=14/180) | 7/180 (3.9%) | Pass |
| Hard attacks | >=14/21 and >=20 percentage points above baseline | 29/29 detected; dev set has 29, target expects 21 | Blocked |
| Hard-benign false alerts vs simulated benign traffic | <=5/36 | 7/36 | Fail |
| Kind accuracy | >=80% of true positives | 96/125 (76.8%) | Fail |
| Confidence quality | AUROC >=0.93 with all 324 scored | 0.9008 (retired token-overwrite scorer; 192 skipped windows scored 0) | Fail |
| Latency | p50 <=400 ms; p95 <=1,200 ms | Evaluator: 0s / 44.2s across windows; model-call-only: 31.8s / 48.8s | Fail |

The run used context 8192. Its per-call latency is the full HTTP request duration, not time-to-first-token. The run used an 8B model on a host with 7.1 GiB RAM; the observed Ollama runner was 6.0 GB and split 54% GPU / 46% CPU, with 2.1 GiB swap in use.

</details>
