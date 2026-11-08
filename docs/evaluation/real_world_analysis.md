# Real-world evaluation: error analysis

Companion to [real_world.md](real_world.md): 14 CISA advisories, scored once on 2026-11-08
with the code frozen at `0f1e6e9`. Reproduce with
`python scripts/analyse_real_world_errors.py`. **Nothing here was used to change the system.**
The real-world set is a test set, and any fix must be chosen on other data (see the end).

## Headline

| Component | Real-world result | Earlier in-distribution result |
|---|---|---|
| IPv4 extraction | 654/657 STIX IPs found; 99% of extracted IPs are in STIX | 1.00 F1 (synthetic) |
| Hash extraction | 100% of the hashes printed in the PDFs found | 1.00 F1 (synthetic) |
| Technique **ID** matching | 329 predictions, all cited by CISA | n/a |
| Name/term matcher (IDs masked) | P 0.70 / R 0.56 (parent level) | n/a |
| **Model-only technique suggestions** | **10% agree with CISA (55 of 550)** | top-1 0.82 on unseen-actor test sentences |

The technique model does **not** transfer to real reports at its current abstention threshold.
This is the most important finding of the project so far, and it is stated in the README.

## 1. Model-only suggestions (550 across 12 advisories, about 46 per advisory)

**Agreement depends strongly on the model's decision score:**

| Decision score | Suggestions | Agree with CISA (parent) |
|---|---|---|
| < 0.25 | 470 (85%) | **0.03** |
| 0.25–0.5 | 28 | 0.36 |
| 0.5–0.75 | 21 | 0.57 |
| ≥ 0.75 | 31 | 0.65 |

* **The score carries real information,** but the abstention threshold was tuned on ATT&CK
  procedure sentences. There, nearly every sentence describes a technique. Real advisories
  are mostly background, mitigations, contact details and table headers, so the threshold
  lets through a large volume of low-score guesses.
* **The most frequent wrong suggestions are generic:** Application Window Discovery (12),
  Process Discovery, Software Discovery, Acquire Infrastructure, Develop Capabilities, Gather
  Victim Org Information (10 each). These are the model's fallback answers for sentences that
  mention software, infrastructure or organisations without describing an attack step.
* **Assertion status doesn't filter them:** 530 of 604 were marked "observed". The cue
  detector finds no hedging in "Organizations should inventory their software", because the
  problem is relevance, not hedging.
* **Not every disagreement is an error.** CISA's lists are incomplete. Still, a 3% agreement
  rate below a score of 0.25 is far too low to blame on that.

**Effect on the risk score:** 9 of the 14 advisories score Critical. Model suggestions feed
the attack-behaviour component (at half weight), so they help saturate the score and reduce
how well it separates advisories. The red-team assessment (Moderate) and the
Snake/Interlock/Androxgh0st advisories (High) are the only ones below Critical.

## 2. Name/term-only matches

Matches found only by technique name or term are rarely exact, though often in the right
family: they agree with CISA 1% of the time exactly and 36% at parent level. The most common
ones are ATT&CK names that are also everyday phrases:
* "IP addresses" → T1590.005, usually from IOC table headers;
* "Remote Services" → T1021;
* "Email Addresses" → T1589.002;
* "Phishing" → T1566, often in mitigation advice;
* "Password Managers", "Create Account", "Web Service".

With IDs masked, the matcher reaches P 0.70 / R 0.56 at parent level, the best precision of
the three methods.

## 3. Indicators

The extractor is strong on IPs and hashes. The misses and extras fall into identifiable
classes:

| Class | Example | Kind of issue |
|---|---|---|
| `.onion` addresses not extracted | `gunrab…dhk4ad.onion` | **Gap.** `.onion` is a special-use name (RFC 7686), not in the IANA root zone, so it fails TLD validation |
| Domain inside a URL not listed separately | `samuelelena.co` (only the full URL is reported) | Design choice (overlap resolution); costs recall against STIX |
| Scheme-less hosts that STIX types as URLs | `vpn677190427.softether.net` | Type mismatch: extracted as domains, compared as URLs |
| URLs cut at a PDF line break | `https://3324.reques`, `.../install.p` | **Gap.** PDF text wraps long URLs; the extractor stops at the line break |
| HTML residue | `...jquery.min.js&nbsp` | **Gap.** Entity text from CISA's HTML-to-PDF conversion is kept |
| Placeholders | `xxx.xxx.xxx.xxx` (a valid `.xxx` TLD) | **Gap.** Redaction patterns aren't recognised |
| Reference links and contacts | `bleepingcomputer.com/...`, `report@cisa.gov` | Correct extraction, not IOCs. They stay "unverified"; no verdict is implied |
| STIX label noise | `sqlmap.py`, `dirsearch.py` typed as domains in CISA's STIX | Gold error; rejecting these is correct |

Hash recall against *all* STIX values is low for SHA-1 (9 of 137), because the advisories
print few of the hashes their STIX bundles contain. Against the printed hashes, recall is 1.00.

## 4. What changes, and how it will be validated

Fixing these by looking at this test set and re-scoring would be tuning on test. The plan:

1. **Product change (needs no threshold from test data):** treat model-only suggestions as
   opt-in leads. Hide them by default in the UI, exclude them from the risk score unless an
   analyst confirms them, and label them clearly in reports.
2. **Threshold work:** choose a real-world abstention threshold on a *separate* development
   set of advisories (not these 14), then test on further unseen advisories.
3. **IOC gaps** (`.onion`, URLs wrapped at a line break, `&nbsp;`, placeholders) are generic
   robustness problems. They'll be fixed with unit tests built from synthetic examples, and
   the effect measured on new documents.

### Status (2026-11-08)
* **Done:** item 1 (`ee278a8`). Leads are hidden by default, flagged in reports, and score
  only once confirmed. Confirming or rejecting a technique re-scores the analysis.
* **Done:** item 3. Line-wrapped URL rejoining, `&nbsp;` removal, placeholder rejection and
  `.onion` support, each covered by synthetic unit tests. The development-split extraction
  report is unchanged. These 14 advisories were **not** re-scored to claim an improvement.
* **In progress:** item 2. A second set of 17 advisories was split once into development (9)
  and test (8). On the development split, the pre-declared rule chose a cut-off of 0.75
  for model-only suggestions ([selection](real_world_threshold.md)). The test split has not
  been scored yet.

The scores in [real_world.md](real_world.md) remain the record for code version `0f1e6e9`.
