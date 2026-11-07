# Extraction evaluation: `test` split, rules-only

* Date: 2026-11-07 15:11 UTC · Code revision: `a0c4cb4` · ATT&CK KB v20.1
* Documents (4): test_01_supply_chain.txt, test_02_credential_phishing.txt, test_03_lockbit.txt, test_04_cryptomining.txt
* Data: **synthetic documents annotated by the project author**. These numbers describe behaviour on this small set only and are not an estimate of real-world accuracy.

## IOCS

| Type | Support | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| domain | 1 | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| email | 1 | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| ipv4 | 5 | 5 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| md5 | 3 | 3 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| sha1 | 2 | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| sha256 | 2 | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| url | 4 | 4 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| **micro** | 18 | 18 | 0 | 0 | **1.00** | **1.00** | **1.00** |

Macro F1 (types with support): **1.00**

## ENTITIES

| Type | Support | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| attack_technique | 14 | 14 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| location | 7 | 0 | 0 | 7 | n/a | 0.00 | n/a |
| malware | 7 | 5 | 0 | 2 | 1.00 | 0.71 | 0.83 |
| organization | 9 | 0 | 0 | 9 | n/a | 0.00 | n/a |
| threat_actor | 3 | 3 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| tool | 6 | 3 | 0 | 3 | 1.00 | 0.50 | 0.67 |
| vulnerability | 1 | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| **micro** | 47 | 26 | 0 | 21 | **1.00** | **0.55** | **0.71** |

Macro F1 (types with support): **0.64**

## Errors

| Document | Task | Type | Error | Value |
|---|---|---|---|---|
| test_01_supply_chain.txt | entities | location | false_negative | `Netherlands` |
| test_01_supply_chain.txt | entities | organization | false_negative | `Kaspersky` |
| test_01_supply_chain.txt | entities | organization | false_negative | `NCSC` |
| test_01_supply_chain.txt | entities | tool | false_negative | `Net` |
| test_02_credential_phishing.txt | entities | malware | false_negative | `POWERSTAR` |
| test_02_credential_phishing.txt | entities | location | false_negative | `Germany` |
| test_02_credential_phishing.txt | entities | location | false_negative | `United Kingdom` |
| test_02_credential_phishing.txt | entities | organization | false_negative | `Google` |
| test_02_credential_phishing.txt | entities | organization | false_negative | `University College London` |
| test_02_credential_phishing.txt | entities | organization | false_negative | `University of Oxford` |
| test_02_credential_phishing.txt | entities | tool | false_negative | `Evilginx` |
| test_03_lockbit.txt | entities | malware | false_negative | `LockBit` |
| test_03_lockbit.txt | entities | location | false_negative | `Italy` |
| test_03_lockbit.txt | entities | organization | false_negative | `ACN` |
| test_03_lockbit.txt | entities | organization | false_negative | `Sophos` |
| test_03_lockbit.txt | entities | tool | false_negative | `wbadmin` |
| test_04_cryptomining.txt | entities | location | false_negative | `Hong Kong` |
| test_04_cryptomining.txt | entities | location | false_negative | `India` |
| test_04_cryptomining.txt | entities | location | false_negative | `Singapore` |
| test_04_cryptomining.txt | entities | organization | false_negative | `Alibaba Cloud` |
| test_04_cryptomining.txt | entities | organization | false_negative | `Trend Micro` |
