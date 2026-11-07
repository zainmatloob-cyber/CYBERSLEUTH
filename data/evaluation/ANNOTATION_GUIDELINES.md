# Annotation Guidelines (v1, 2026-11-07)

Gold labels are written **from the document text**, following these rules. They are
never derived from extractor output. Each document has a `<name>.gold.json` file.

## Unit of evaluation
**Document level, unique values.** Each gold item is a `(type, value)` pair that appears
in the document at least once. Repeated mentions count once. This matches how CyberSleuth
reports results (de-duplicated indicators and entities).

## IOCs
| Type | Annotate | Do not annotate |
|---|---|---|
| `ipv4` | Every syntactically valid IPv4 address, including private and documentation ranges. Defanged forms count, written refanged (`203.0.113[.]5` → `203.0.113.5`). An address followed by `:port` is still annotated. | Version or build strings (`version 3.2.1.4`, `v2.0.1.7`); an IP that is the host of a URL (the URL covers it) |
| `domain` | Every domain name meant as a network location, written lowercase and refanged | File names (`invoice.zip`, `update.sh`, `config.json`); .NET namespaces (`System.Management.Automation`); a domain that is part of a URL or email address |
| `url` | Every URL. Scheme and host lowercase, path as written, trailing sentence punctuation excluded, refanged (`hxxp` → `http`) | — |
| `email` | Every email address, lowercase and refanged | — |
| `md5` / `sha1` / `sha256` | Hex digests of 32/40/64 characters, lowercase | Placeholder numbers or strings explicitly described as "not a hash" |
| `cve` | Every CVE ID, as `CVE-YYYY-NNNN` | — |

## Entities
Entities are evaluated as **mentions**: a negated mention ("Phishing was not involved")
still counts. Whether something actually happened is decided by later stages (Phase 3).

| Type | Annotate | Canonical value |
|---|---|---|
| `malware` | Named malware families and ransomware | ATT&CK primary name if listed in ATT&CK, otherwise the name as written |
| `threat_actor` | Named groups and clusters, including vendor codes (UNC, Storm-, FIN, APT) | ATT&CK primary name if listed (aliases map to it), otherwise as written |
| `tool` | Named software that attackers use in the described activity: offensive tools, abused admin utilities, remote-access software | ATT&CK primary name if listed; otherwise the curated canonical name or as written |
| `vulnerability` | **Named** vulnerabilities (Log4Shell, Zerologon). CVE IDs are evaluated as IOCs, not here | Common name |
| `attack_technique` | Mentions of behaviours in the curated technique vocabulary (`data/knowledge_base/curated_entities.json`, `attack_techniques`), *however they are phrased*. Behaviours outside that vocabulary are not annotated | Curated canonical name |
| `organization` | Named companies, agencies, universities and vendors (victims, responders, providers). Not threat actors, not products | Name without a leading "the" or a possessive "'s" |
| `location` | Named countries, cities and regions | Name as written, without "the" |

Nationality adjectives ("Dutch", "Polish"), unnamed organisations ("a hospital"), protocols
(RDP, SSH, HTTPS) and generic words ("the operators") are not annotated.

## Process
1. Write the document. It contains realistic traps: filenames on TLD-like extensions,
   version strings, ambiguous names, and phrasings outside the extractor's patterns.
2. Annotate by reading the text. ATT&CK may be consulted to find canonical names; the
   extractor may not.
3. **Dev set**: may be used to find and fix bugs. **Test set**: scored once, after all
   fixes, and reported as is.
