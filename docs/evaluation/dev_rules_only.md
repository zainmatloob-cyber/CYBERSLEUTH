# Extraction evaluation: `dev` split, rules-only

* Date: 2026-11-07 15:10 UTC · Code revision: `a0c4cb4` · ATT&CK KB v20.1
* Documents (4): dev_01_ransomware.txt, dev_02_espionage.txt, dev_03_banking.txt, dev_04_edge_devices.txt
* Data: **synthetic documents annotated by the project author**. These numbers describe behaviour on this small set only and are not an estimate of real-world accuracy.

## IOCS

| Type | Support | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| cve | 3 | 3 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| domain | 4 | 4 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| email | 3 | 3 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| ipv4 | 8 | 8 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| md5 | 2 | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| sha1 | 2 | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| sha256 | 3 | 3 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| url | 4 | 4 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| **micro** | 29 | 29 | 0 | 0 | **1.00** | **1.00** | **1.00** |

Macro F1 (types with support): **1.00**

## ENTITIES

| Type | Support | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| attack_technique | 15 | 14 | 0 | 1 | 1.00 | 0.93 | 0.97 |
| location | 9 | 0 | 0 | 9 | n/a | 0.00 | n/a |
| malware | 4 | 4 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| organization | 9 | 0 | 0 | 9 | n/a | 0.00 | n/a |
| threat_actor | 4 | 4 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| tool | 14 | 13 | 0 | 1 | 1.00 | 0.93 | 0.96 |
| vulnerability | 2 | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| **micro** | 57 | 37 | 0 | 20 | **1.00** | **0.65** | **0.79** |

Macro F1 (types with support): **0.70**

## Errors

| Document | Task | Type | Error | Value |
|---|---|---|---|---|
| dev_01_ransomware.txt | entities | tool | false_negative | `Tor` |
| dev_01_ransomware.txt | entities | location | false_negative | `Portugal` |
| dev_01_ransomware.txt | entities | attack_technique | false_negative | `Data Encryption for Impact` |
| dev_01_ransomware.txt | entities | organization | false_negative | `CISA` |
| dev_01_ransomware.txt | entities | organization | false_negative | `Mandiant` |
| dev_01_ransomware.txt | entities | organization | false_negative | `MEGA` |
| dev_01_ransomware.txt | entities | organization | false_negative | `Microsoft` |
| dev_02_espionage.txt | entities | location | false_negative | `Brussels` |
| dev_02_espionage.txt | entities | location | false_negative | `Norway` |
| dev_02_espionage.txt | entities | location | false_negative | `Warsaw` |
| dev_02_espionage.txt | entities | organization | false_negative | `CERT Polska` |
| dev_02_espionage.txt | entities | organization | false_negative | `ESET` |
| dev_02_espionage.txt | entities | organization | false_negative | `Ministry of Foreign Affairs` |
| dev_03_banking.txt | entities | location | false_negative | `Brazil` |
| dev_03_banking.txt | entities | location | false_negative | `Latin America` |
| dev_03_banking.txt | entities | location | false_negative | `Mexico` |
| dev_03_banking.txt | entities | organization | false_negative | `Banco Exemplo` |
| dev_04_edge_devices.txt | entities | location | false_negative | `Canada` |
| dev_04_edge_devices.txt | entities | location | false_negative | `Estonia` |
| dev_04_edge_devices.txt | entities | organization | false_negative | `Palo Alto Networks` |
