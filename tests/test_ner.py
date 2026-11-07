"""Tests for cybersecurity entity recognition (src/nlp/entity_extractor.py, entity_kb.py)."""

from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path

import pytest

from src.ingestion.models import ExtractedDocument, FileType, PageText
from src.ingestion.pipeline import ingest
from src.nlp.entity_extractor import EntityExtractor, load_spacy_model
from src.nlp.entity_kb import KB_DIR, load_knowledge_base
from src.nlp.entity_models import EntitySource, EntityType
from src.nlp.preprocessing import split_sentences
from src.utils.exceptions import KnowledgeBaseError, ModelNotAvailableError

SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"
HAS_MODEL = importlib.util.find_spec("en_core_web_sm") is not None
needs_model = pytest.mark.skipif(not HAS_MODEL, reason="en_core_web_sm not installed")


@pytest.fixture(scope="module")
def rules() -> EntityExtractor:
    """Deterministic rules only (blank tokenizer, no statistical model)."""
    return EntityExtractor(model=None)


@pytest.fixture(scope="module")
def full() -> EntityExtractor:
    if not HAS_MODEL:
        pytest.skip("en_core_web_sm not installed")
    return EntityExtractor()


def _doc(*pages: str) -> ExtractedDocument:
    page_list = [PageText(i + 1, t) for i, t in enumerate(pages)]
    return ExtractedDocument("x.txt", FileType.TXT, "0" * 64, 1, page_list,
                             sentences=split_sentences(page_list))


def _found(extractor: EntityExtractor, text: str) -> set[tuple[EntityType, str]]:
    return {(e.entity_type, e.name) for e in extractor.extract(_doc(text))}


# --- knowledge base -----------------------------------------------------------


def test_knowledge_base_loads_versioned_data():
    kb = load_knowledge_base()
    assert kb.versions["attack"] == "20.1"
    assert len(kb.attack_forms) > 1500
    assert [(e.kb_id, e.entity_type) for e in kb.attack_forms["Fancy Bear"]] == [
        ("G0007", EntityType.THREAT_ACTOR)
    ]


def test_curated_entries_do_not_duplicate_attack():
    kb = load_knowledge_base()
    assert not set(kb.curated_forms) & {form.lower() for form in kb.attack_forms}


def test_rule_file_typo_is_rejected(tmp_path):
    for name in ("attack_entities.json", "curated_entities.json", "entity_rules.json"):
        shutil.copy(KB_DIR / name, tmp_path / name)
    rules_path = tmp_path / "entity_rules.json"
    data = json.loads(rules_path.read_text(encoding="utf-8"))
    data["context_required_forms"].append("Emotett")  # typo
    rules_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(KnowledgeBaseError, match="Emotett"):
        load_knowledge_base(tmp_path)


def test_missing_kb_file_raises(tmp_path):
    with pytest.raises(KnowledgeBaseError):
        load_knowledge_base(tmp_path)


def test_duplicate_curated_variant_rejected(tmp_path):
    for name in ("attack_entities.json", "curated_entities.json", "entity_rules.json"):
        shutil.copy(KB_DIR / name, tmp_path / name)
    path = tmp_path / "curated_entities.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["tools"].append({"name": "Dup", "variants": ["PowerShell"]})
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(KnowledgeBaseError, match="Duplicate"):
        load_knowledge_base(tmp_path)


# --- ATT&CK knowledge-base matching -------------------------------------------


def test_aliases_resolve_to_canonical_entity(rules):
    (entity,) = rules.extract(_doc("APT28, also known as Fancy Bear, was active."))
    assert (entity.name, entity.kb_id, entity.source) == ("APT28", "G0007", EntitySource.ATTACK_KB)
    assert entity.count == 2 and entity.aliases_seen == ["Fancy Bear"]


def test_distinctive_names_match_case_insensitively(rules):
    assert _found(rules, "They ran mimikatz and EMOTET.") == {
        (EntityType.TOOL, "Mimikatz"), (EntityType.MALWARE, "Emotet"),
    }


def test_attack_classification_is_kept(rules):
    """ATT&CK classifies Cobalt Strike as malware; the KB label is not overridden."""
    assert _found(rules, "Operators deployed Cobalt Strike.") == {
        (EntityType.MALWARE, "Cobalt Strike")
    }


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Cuba ransomware encrypted the servers.", {(EntityType.MALWARE, "Cuba")}),
        ("Trade with Cuba grew last year.", set()),
        ("The Silence group targeted banks.", {(EntityType.THREAT_ACTOR, "Silence")}),
        ("Silence fell over the room.", set()),
        ("The analyst ran Net to enumerate users.", {(EntityType.TOOL, "Net")}),
        ("Net income rose sharply.", set()),
        ("The Royal ransomware variant spread.", {(EntityType.MALWARE, "Royal")}),
        ("A royal visit took place.", set()),
    ],
)
def test_ambiguous_names_need_context(rules, text, expected):
    assert _found(rules, text) == expected


def test_blocked_forms_never_match(rules):
    assert _found(rules, "The tool ran at midnight via the route command.") == set()


@pytest.mark.parametrize(
    ("text", "entity_type", "kb_id"),
    [
        ("The Sofacy group was attributed.", EntityType.THREAT_ACTOR, "G0007"),
        ("A Sofacy backdoor sample was found.", EntityType.MALWARE, "S0137"),
    ],
)
def test_shared_forms_disambiguated_by_context(rules, text, entity_type, kb_id):
    (entity,) = rules.extract(_doc(text))
    assert (entity.entity_type, entity.kb_id) == (entity_type, kb_id)
    assert entity.alternatives  # the other reading is recorded, not discarded


def test_alternatives_merge_across_mentions(rules):
    (entity,) = rules.extract(_doc("APT28 was busy. The Sofacy group struck again."))
    assert entity.kb_id == "G0007" and "S0137" in entity.alternatives


# --- curated knowledge base ---------------------------------------------------


def test_curated_tools_vulnerabilities_techniques(rules):
    entities = {e.name: e for e in rules.extract(_doc(
        "They exploited Log4Shell, sent spear-phishing emails and abused PowerShell."
    ))}
    assert entities["Log4Shell"].entity_type is EntityType.VULNERABILITY
    assert entities["Log4Shell"].attributes == {"cve": "CVE-2021-44228"}
    assert entities["Spearphishing"].entity_type is EntityType.ATTACK_TECHNIQUE
    assert "Phishing" not in entities  # longer "spear-phishing" wins the overlap
    assert entities["PowerShell"].source is EntitySource.CURATED_KB


# --- actor naming patterns ----------------------------------------------------


@pytest.mark.parametrize(
    ("text", "name", "source"),
    [
        ("UNC9876 was observed.", "UNC9876", EntitySource.ACTOR_PATTERN),
        ("Storm-9999 was observed.", "Storm-9999", EntitySource.ACTOR_PATTERN),
        ("DEV 9999 was observed.", "DEV-9999", EntitySource.ACTOR_PATTERN),
        ("Velvet Typhoon was observed.", "Velvet Typhoon", EntitySource.ACTOR_PATTERN),
        ("APT 41 was observed.", "APT41", EntitySource.ATTACK_KB),  # upgraded to KB entity
    ],
)
def test_actor_patterns(rules, text, name, source):
    (entity,) = rules.extract(_doc(text))
    assert (entity.entity_type, entity.name, entity.source) == (
        EntityType.THREAT_ACTOR, name, source,
    )


@pytest.mark.parametrize("text", ["APT1234 is not valid.", "TA12 is too short.", "XAPT28x"])
def test_actor_pattern_digit_rules(rules, text):
    assert _found(rules, text) == set()


# --- evidence -----------------------------------------------------------------


def test_mentions_point_back_to_source(rules):
    doc = _doc("Intro sentence. Later Emotet was dropped.", "Page two mentions Emotet too.")
    (entity,) = rules.extract(doc)
    assert entity.count == 2
    for mention in entity.mentions:
        page = doc.pages[mention.page_number - 1]
        assert page.text[mention.char_start : mention.char_end] == mention.text == "Emotet"
        assert doc.sentences[mention.sentence_index].page_number == mention.page_number
    assert entity.mentions[0].context == "Later Emotet was dropped."


def test_rule_entities_have_no_invented_confidence(rules):
    assert all(e.confidence is None for e in rules.extract(_doc("Emotet and APT28.")))


def test_sentences_computed_when_missing(rules):
    pages = [PageText(1, "Emotet was seen.")]
    doc = ExtractedDocument("x", FileType.TXT, "0" * 64, 1, pages)  # no sentences yet
    assert [e.name for e in rules.extract(doc)] == ["Emotet"]


def test_sample_advisory_rule_entities(rules):
    doc = ingest((SAMPLES / "synthetic_advisory.txt").read_bytes(), "a.txt")
    assert _found_doc(rules, doc) == {
        (EntityType.TOOL, "PowerShell"),
        (EntityType.ATTACK_TECHNIQUE, "Phishing"),
        (EntityType.ATTACK_TECHNIQUE, "Spearphishing"),
        (EntityType.ATTACK_TECHNIQUE, "Data Encryption for Impact"),
    }


def _found_doc(extractor, doc):
    return {(e.entity_type, e.name) for e in extractor.extract(doc)}


# --- statistical model --------------------------------------------------------


def test_missing_model_raises_clear_error():
    with pytest.raises(ModelNotAvailableError, match="spacy download"):
        load_spacy_model("xx_not_a_real_model")


@needs_model
def test_model_finds_organizations_and_locations(full):
    entities = {(e.entity_type, e.name): e for e in full.extract(_doc(
        "The attackers targeted Microsoft and several banks in Germany."
    ))}
    org = entities[(EntityType.ORGANIZATION, "Microsoft")]
    assert org.source is EntitySource.MODEL and org.confidence is None
    assert (EntityType.LOCATION, "Germany") in entities


@needs_model
def test_kb_takes_precedence_over_model(full):
    found = _found(full, "Operators deployed Cobalt Strike against Acme Corp in France.")
    assert (EntityType.MALWARE, "Cobalt Strike") in found
    assert (EntityType.ORGANIZATION, "Cobalt Strike") not in found


@needs_model
@pytest.mark.parametrize(
    "text", ["Technical Details.", "Patch CVE-2024-3400 now.", "Visit update-service.example.net."]
)
def test_model_noise_is_filtered(full, text):
    assert not {e for e in full.extract(_doc(text)) if e.source is EntitySource.MODEL}


@needs_model
def test_country_vs_malware_resolved_by_context(full):
    found = _found(full, "Trade with Cuba grew. Cuba ransomware encrypted servers.")
    assert {(EntityType.LOCATION, "Cuba"), (EntityType.MALWARE, "Cuba")} <= found
