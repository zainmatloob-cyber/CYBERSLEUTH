"""Unit tests for the real-world (CISA) evaluation logic. No downloaded documents needed."""

from __future__ import annotations

import pytest

from src.evaluation import real_world as rw
from src.intelligence.assertion import AssertionStatus
from src.intelligence.attack_kb import default_technique_kb
from src.intelligence.mitre_mapper import MappingMethod, TechniqueEvidence, TechniqueMapping
from src.nlp.ioc_models import IOCType


@pytest.fixture(scope="module")
def kb():
    return default_technique_kb()


def _mapping(technique_id: str, *methods: MappingMethod,
             status: AssertionStatus = AssertionStatus.OBSERVED) -> TechniqueMapping:
    return TechniqueMapping(technique_id, "name", ("tactic",), "https://attack.mitre.org/",
                            [TechniqueEvidence(0, 1, "s", m, status) for m in methods])


def test_cited_techniques_resolves_revoked_and_reports_unknown(kb):
    text = ("Actors used T1190 and T1059.001 [T1574.002]. Table: T9999. "
            "Not IDs: AT1234X, T1059.0012, ST1105.")
    cited = rw.cited_techniques(text, kb)
    assert {"T1190", "T1059.001", "T1574.001"} <= cited.resolved
    assert cited.translated["T1574.002"] == "T1574.001"
    assert cited.unresolved == ["T9999"]
    assert "T1105" not in cited.resolved and "T1234" not in cited.resolved


def test_mask_removes_technique_and_tactic_ids():
    assert rw.mask_technique_ids("Phishing [T1566.001] in TA0001; ST1105 stays") == \
        "Phishing [] in ; ST1105 stays"


def test_parents(kb):
    assert rw.parents({"T1059.001", "T1190"}, kb) == {"T1059", "T1190"}


def test_prediction_groups_and_agreement(kb):
    mappings = [
        _mapping("T1190", MappingMethod.EXPLICIT_ID, MappingMethod.MODEL),
        _mapping("T1566.001", MappingMethod.EXPLICIT_NAME),
        _mapping("T1059", MappingMethod.MODEL),
        _mapping("T1027", MappingMethod.MODEL),
        _mapping("T1486", MappingMethod.MODEL, status=AssertionStatus.NEGATED),  # excluded
    ]
    assert [rw.prediction_group(m) for m in mappings[:3]] == ["id", "name_or_term",
                                                              "model_only"]
    gold = {"T1190", "T1566.002", "T1059.001"}
    groups = rw.group_agreement(mappings, gold, kb)
    assert groups["id"].as_dict()["agreement_exact"] == 1.0
    assert groups["name_or_term"].cited_exact == 0 and groups["name_or_term"].cited_parent == 1
    model = groups["model_only"].as_dict()
    assert model["predicted"] == 2 and model["agreement_parent"] == 0.5
    counts = rw.technique_counts(mappings, gold, kb, groups={"model_only"})
    assert counts["parent"].tp == 1 and counts["parent"].fp == 1 and counts["parent"].fn == 2


STIX = {"type": "bundle", "objects": [
    {"type": "indicator", "pattern": "[ipv4-addr:value = '198.51.100.7']"},
    {"type": "indicator", "pattern": "[ipv4-addr:value = '203.0.113.0/24']"},  # range: skipped
    {"type": "indicator", "pattern": "[domain-name:value = 'Evil.Example.com'] OR "
                                     "[url:value = 'http://evil.example.com/x/']"},
    {"type": "indicator", "pattern": "[file:hashes.'SHA-256' = 'AB" + "c" * 62 + "']"},
    {"type": "indicator", "pattern": "[file:hashes.MD5 = '" + "d" * 32 + "']"},
    {"type": "file", "hashes": {"SHA-1": "e" * 40}},
    {"type": "email-addr", "value": "bad@phish.example.org"},
    {"type": "ipv4-addr", "value": "192.0.2.1"},
]}


def test_stix_indicators():
    found = rw.stix_indicators(STIX)
    assert found[IOCType.IPV4] == {"198.51.100.7", "192.0.2.1"}
    assert found[IOCType.DOMAIN] == {"evil.example.com"}
    assert found[IOCType.URL] == {"http://evil.example.com/x"}
    assert found[IOCType.SHA256] == {"ab" + "c" * 62}
    assert found[IOCType.MD5] == {"d" * 32} and found[IOCType.SHA1] == {"e" * 40}
    assert found[IOCType.EMAIL] == {"bad@phish.example.org"}


def test_ioc_agreement_separates_printed_values():
    stix = rw.stix_indicators(STIX)
    ours = {t: set() for t in rw.COMPARED_IOC_TYPES}
    ours[IOCType.IPV4] = {"198.51.100.7", "10.0.0.1"}
    text = rw.refang_text("Beacon to 198.51.100[.]7 and hxxp://evil[.]example[.]com/x/")
    result = rw.ioc_agreement(ours, stix, text)
    ipv4 = result["ipv4"].as_dict()
    assert ipv4 == {"extracted": 2, "stix": 2, "stix_in_text": 1, "matched": 1,
                    "extracted_in_stix": 0.5, "stix_found": 0.5, "printed_stix_found": 1.0}
    assert result["url"].in_text == 1 and result["url"].as_dict()["extracted_in_stix"] is None


def test_refang_text():
    assert rw.refang_text("hxxps://a[.]b and x[at]y(.)z") == "https://a.b and x@y.z"


# --- end-to-end smoke test of the evaluation script (synthetic stand-in documents) -------


def test_evaluation_script_runs_end_to_end(tmp_path, monkeypatch):
    import hashlib
    import importlib.util
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    if not (root / "models" / "technique_model.joblib").exists():
        pytest.skip("trained technique model not available")
    spec = importlib.util.spec_from_file_location(
        "evaluate_real_world", root / "scripts" / "evaluate_real_world.py")
    script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(script)

    raw = tmp_path / "raw"
    raw.mkdir()
    pdf = (root / "data" / "samples" / "synthetic_advisory.pdf").read_bytes()
    (raw / "doc1.pdf").write_bytes(pdf)
    stix = json.dumps(STIX).encode()
    (raw / "doc1.stix.json").write_bytes(stix)
    plain = (root / "data" / "samples" / "synthetic_advisory.txt").read_bytes()
    (raw / "doc2.pdf").write_bytes(pdf)  # same PDF, but gold is forced empty below
    (raw / "doc2.stix.xml").write_text(STIX1, encoding="utf-8")
    manifest = {"documents": [{
        "id": "doc1", "group": "test", "title": "Synthetic", "pdf_name": "x", "stix_name": "y",
        "pdf_sha256": hashlib.sha256(pdf).hexdigest(),
        "stix_sha256": hashlib.sha256(stix).hexdigest()}, {
        "id": "doc2", "group": "test", "title": "No ATT&CK", "pdf_name": "x",
        "stix_name": "y.xml", "pdf_sha256": hashlib.sha256(pdf).hexdigest(),
        "stix_sha256": hashlib.sha256((raw / "doc2.stix.xml").read_bytes()).hexdigest()}]}
    assert plain  # the sample set exists
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    for name, value in {"MANIFEST": tmp_path / "manifest.json", "RAW_DIR": raw,
                        "GOLD_PATH": tmp_path / "gold.json",
                        "OUT_JSON": tmp_path / "out.json", "OUT_MD": tmp_path / "out.md",
                        "ROOT": tmp_path}.items():
        monkeypatch.setattr(script, name, value)
    original = script.build_gold

    def gold_without_doc2_techniques(documents, kb):
        gold = original(documents, kb)
        # The stand-in PDF cites no IDs: give doc1 technique gold so that path is exercised,
        # and keep doc2 empty to simulate an advisory without an ATT&CK section.
        gold["documents"]["doc1"]["techniques"] = ["T1486", "T1566"]
        gold["documents"]["doc2"]["techniques"] = []
        return gold

    monkeypatch.setattr(script, "build_gold", gold_without_doc2_techniques)
    monkeypatch.setattr("sys.argv", ["evaluate_real_world.py", "--final"])
    assert script.main() == 0
    results = json.loads((tmp_path / "out.json").read_text())
    doc2 = results["documents"]["doc2"]
    assert doc2["techniques_evaluated"] is False and "published_groups" not in doc2
    assert "ioc" in doc2  # still used for the indicator comparison
    doc1 = results["documents"]["doc1"]
    assert doc1["techniques_evaluated"] is True and doc1["published"]["exact"]["support"] == 2
    assert set(results["overall"]["published_groups"]) == {"id", "name_or_term", "model_only"}
    assert "Real-world evaluation" in (tmp_path / "out.md").read_text(encoding="utf-8")


def test_evaluation_script_refuses_missing_files(tmp_path, monkeypatch):
    import importlib.util
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location(
        "evaluate_real_world", root / "scripts" / "evaluate_real_world.py")
    script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(script)
    (tmp_path / "m.json").write_text(json.dumps({"documents": [
        {"id": "x", "pdf_name": "u", "stix_name": None, "pdf_sha256": "0"}]}))
    monkeypatch.setattr(script, "MANIFEST", tmp_path / "m.json")
    monkeypatch.setattr(script, "RAW_DIR", tmp_path)
    with pytest.raises(SystemExit, match="missing x.pdf"):
        script.load_documents()


# --- STIX 1.x XML -------------------------------------------------------------------

STIX1 = """<?xml version="1.0" encoding="utf-8" ?>
<stix:STIX_Package xmlns:stix="http://stix.mitre.org/stix-1"
    xmlns:cybox="http://cybox.mitre.org/cybox-2"
    xmlns:cyboxCommon="http://cybox.mitre.org/common-2"
    xmlns:AddressObj="http://cybox.mitre.org/objects#AddressObject-2"
    xmlns:DomainNameObj="http://cybox.mitre.org/objects#DomainNameObject-1"
    xmlns:URIObj="http://cybox.mitre.org/objects#URIObject-2">
  <cybox:Object><cybox:Properties>
    <AddressObj:Address_Value condition="Equals">198.51.100.7##comma##203.0.113.9
    </AddressObj:Address_Value>
  </cybox:Properties></cybox:Object>
  <cybox:Object><cybox:Properties>
    <AddressObj:Address_Value>Bad@Phish.Example.org</AddressObj:Address_Value>
  </cybox:Properties></cybox:Object>
  <cybox:Object><cybox:Properties>
    <DomainNameObj:Value>Evil.Example.com</DomainNameObj:Value>
    <URIObj:Value>http://evil.example.com/x/</URIObj:Value>
    <cyboxCommon:Simple_Hash_Value>E574AD52562FCE9EA506F47E79516A52</cyboxCommon:Simple_Hash_Value>
    <cyboxCommon:Simple_Hash_Value>not-a-hash</cyboxCommon:Simple_Hash_Value>
  </cybox:Properties></cybox:Object>
</stix:STIX_Package>"""


def test_stix1_indicators():
    found = rw.stix1_indicators(STIX1)
    assert found[IOCType.IPV4] == {"198.51.100.7", "203.0.113.9"}
    assert found[IOCType.EMAIL] == {"bad@phish.example.org"}
    assert found[IOCType.DOMAIN] == {"evil.example.com"}
    assert found[IOCType.URL] == {"http://evil.example.com/x"}
    assert found[IOCType.MD5] == {"e574ad52562fce9ea506f47e79516a52"}
    assert not found[IOCType.SHA1] and not found[IOCType.SHA256]


@pytest.mark.parametrize("payload", [
    '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">]><a>&lol;</a>',
    '<?xml version="1.0"?><!DOCTYPE a SYSTEM "file:///etc/passwd"><a/>',
], ids=["entity-expansion", "external-dtd"])
def test_stix1_refuses_dtds_and_entities(payload):
    with pytest.raises(rw.UnsafeXMLError):
        rw.stix1_indicators(payload)


def test_load_stix_picks_parser_by_extension(tmp_path):
    import json
    (tmp_path / "a.stix.xml").write_text(STIX1, encoding="utf-8")
    (tmp_path / "b.stix.json").write_text(json.dumps(STIX), encoding="utf-8")
    assert rw.load_stix(tmp_path / "a.stix.xml")[IOCType.MD5]
    assert rw.load_stix(tmp_path / "b.stix.json")[IOCType.SHA1] == {"e" * 40}
