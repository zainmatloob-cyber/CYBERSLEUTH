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
    assert (tmp_path / "gold.json").exists()  # gold is written next to the manifest


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


# --- manifests (src/evaluation/manifest.py) ------------------------------------------


def test_manifest_reads_both_stix_formats_and_names_local_files(tmp_path):
    from src.evaluation import manifest as rm

    legacy = {"id": "a1", "pdf_name": "A1.pdf", "pdf_sha256": "p",
              "stix_name": "A1.stix_.xml", "stix_sha256": "s"}
    files = rm.manifest_files(legacy, tmp_path)
    assert [(f.kind, f.path.name, f.sha256) for f in files] == [
        ("pdf", "a1.pdf", "p"), ("stix", "a1.stix.xml", "s")]

    several = {"id": "b2", "pdf_name": "B2.pdf", "stix": [
        {"name": "B2 part one.stix.xml", "sha256": None},
        {"name": "B2-2.stix_.json", "sha256": "t"}]}
    names = [f.path.name for f in rm.manifest_files(several, tmp_path)]
    assert names == ["b2.pdf", "b2.stix-1.xml", "b2.stix-2.json"]
    assert rm.manifest_files({"id": "c3", "pdf_name": "C3.pdf"}, tmp_path)[0].kind == "pdf"
    assert len(rm.manifest_files({"id": "c3", "pdf_name": "C3.pdf",
                                  "stix_name": None}, tmp_path)) == 1


def test_manifest_record_hash_keeps_the_format(tmp_path):
    from src.evaluation import manifest as rm

    legacy = {"id": "a1", "pdf_name": "A1.pdf", "stix_name": "A1.json"}
    for f in rm.manifest_files(legacy, tmp_path):
        rm.record_hash(legacy, f, f"h-{f.kind}")
    assert legacy["pdf_sha256"] == "h-pdf" and legacy["stix_sha256"] == "h-stix"
    assert "stix" not in legacy

    several = {"id": "b2", "pdf_name": "B2.pdf",
               "stix": [{"name": "x.xml"}, {"name": "y.json"}]}
    for f in rm.manifest_files(several, tmp_path):
        rm.record_hash(several, f, f.path.name)
    assert [e["sha256"] for e in several["stix"]] == ["b2.stix-1.xml", "b2.stix-2.json"]
    assert "stix_sha256" not in several


def test_manifest_raw_dir(tmp_path):
    from src.evaluation import manifest as rm

    assert rm.raw_dir({"raw_dir": "data/raw/x"}, tmp_path) == tmp_path / "data/raw/x"
    assert rm.raw_dir({}, tmp_path) == tmp_path / rm.DEFAULT_RAW_DIR
    assert rm.raw_dir({}, tmp_path, tmp_path / "d") == tmp_path / "d"


def test_load_stix_files_merges_bundles(tmp_path):
    import json
    (tmp_path / "a.stix-1.xml").write_text(STIX1, encoding="utf-8")
    (tmp_path / "a.stix-2.json").write_text(json.dumps(STIX), encoding="utf-8")
    merged = rw.load_stix_files([tmp_path / "a.stix-1.xml", tmp_path / "a.stix-2.json"])
    one, two = rw.load_stix(tmp_path / "a.stix-1.xml"), rw.load_stix(tmp_path / "a.stix-2.json")
    for ioc_type in set(one) | set(two):
        assert merged[ioc_type] == one.get(ioc_type, set()) | two.get(ioc_type, set())
    assert merged[IOCType.MD5] and merged[IOCType.SHA1] == {"e" * 40}


def _evaluation_script():
    import importlib.util
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location(
        "evaluate_real_world", root / "scripts" / "evaluate_real_world.py")
    script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(script)
    return script


def test_load_documents_uses_raw_dir_and_several_stix_files(tmp_path, monkeypatch):
    import hashlib
    import json

    script = _evaluation_script()
    raw = tmp_path / "data" / "raw" / "set2"
    raw.mkdir(parents=True)
    contents = {"d1.pdf": b"%PDF-1.4 x", "d1.stix-1.xml": STIX1.encode(),
                "d1.stix-2.json": json.dumps(STIX).encode()}
    for name, data in contents.items():
        (raw / name).write_bytes(data)
    digest = {n: hashlib.sha256(d).hexdigest() for n, d in contents.items()}
    manifest = {"raw_dir": "data/raw/set2", "documents": [{
        "id": "d1", "pdf_name": "D1.pdf", "pdf_sha256": digest["d1.pdf"],
        "stix": [{"name": "D1.xml", "sha256": digest["d1.stix-1.xml"]},
                 {"name": "D1-2.json", "sha256": digest["d1.stix-2.json"]}]}]}
    monkeypatch.setattr(script, "ROOT", tmp_path)
    doc = script.load_documents(manifest)[0]
    assert doc["pdf_path"] == raw / "d1.pdf"
    assert doc["stix_paths"] == [raw / "d1.stix-1.xml", raw / "d1.stix-2.json"]

    manifest["documents"][0]["stix"][1]["sha256"] = "0" * 64
    with pytest.raises(SystemExit, match="hash mismatch d1.stix-2.json"):
        script.load_documents(manifest)


def test_final_scoring_refused_for_an_unsplit_manifest(tmp_path, monkeypatch):
    import json

    script = _evaluation_script()
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"final_scoring": False, "documents": []}))
    monkeypatch.setattr("sys.argv", ["evaluate_real_world.py", "--manifest", str(path),
                                     "--final"])
    with pytest.raises(SystemExit, match="not open for final scoring"):
        script.main()
    assert not (tmp_path / "gold.json").exists()  # refused before anything is written


# --- development/test split ----------------------------------------------------------


def _script(name):
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parent.parent / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _docs():
    years = ["2022"] * 7 + ["2023"] * 7 + ["2024", "2025", "2025"]
    return [{"id": f"d{n:02d}", "published": f"{y}-01"} for n, y in enumerate(years)]


def test_split_is_stratified_reproducible_and_order_independent():
    script = _script("split_real_world")
    docs = _docs()
    first = script.split(docs)
    assert first == script.split(list(reversed(docs)))  # file order doesn't matter
    for period, (dev, test) in script.ALLOCATION.items():
        ids = [d["id"] for d in docs if script.period(d["published"]) == period]
        assert sum(first[i] == "dev" for i in ids) == dev
        assert sum(first[i] == "test" for i in ids) == test
    assert script.split(docs, seed=1) != first  # the seed, not the order, decides


def test_split_refuses_a_mismatched_allocation():
    script = _script("split_real_world")
    with pytest.raises(ValueError, match="allocation"):
        script.split(_docs()[:-1])
    with pytest.raises(ValueError, match="periods"):
        script.split([{"id": "x", "published": "2021-01"}] + _docs())


def test_split_is_never_redrawn(tmp_path, monkeypatch):
    import json

    script = _script("split_real_world")
    path = tmp_path / "set9" / "manifest.json"
    path.parent.mkdir()
    path.write_text(json.dumps({"final_scoring": False, "documents": _docs()}))
    monkeypatch.setattr("sys.argv", ["split_real_world.py", "--manifest", str(path)])
    assert script.main() == 0
    manifest = json.loads(path.read_text())
    assert manifest["final_scoring"] == "test" and manifest["split"]["seed"] == script.SEED
    assert manifest["report_stem"] == "real_world_set9_test"
    assert {d["split"] for d in manifest["documents"]} == {"dev", "test"}
    with pytest.raises(SystemExit, match="never redrawn"):
        script.main()


def test_in_split_and_final_scoring_rules():
    from src.evaluation import manifest as rm

    docs = [{"id": "a", "split": "dev"}, {"id": "b", "split": "test"}]
    split = {"split": {"seed": 1}, "final_scoring": "test"}
    assert [d["id"] for d in rm.in_split(split, docs, "dev")] == ["a"]
    assert [d["id"] for d in rm.in_split(split, docs, "test")] == ["b"]
    with pytest.raises(SystemExit, match="choose --split"):
        rm.in_split(split, docs, None)
    with pytest.raises(SystemExit, match="no development/test split"):
        rm.in_split({}, docs, "dev")
    assert rm.in_split({}, docs, None) == docs

    rm.check_final_scoring(split, "test")
    rm.check_final_scoring({}, None)  # the first set: no restriction
    for manifest, chosen in ((split, "dev"), (split, None)):
        with pytest.raises(SystemExit, match="only on --split test"):
            rm.check_final_scoring(manifest, chosen)
    with pytest.raises(SystemExit, match="not open"):
        rm.check_final_scoring({"final_scoring": False}, "test")


def test_error_analysis_refuses_the_test_split(tmp_path, monkeypatch):
    script = _script("analyse_real_world_errors")
    monkeypatch.setattr("sys.argv", ["analyse_real_world_errors.py", "--manifest",
                                     str(tmp_path / "m.json"), "--split", "test"])
    with pytest.raises(SystemExit, match="only after its final scoring"):
        script.main()


# --- real-world cut-off selection -----------------------------------------------------


def test_threshold_rule_picks_the_lowest_candidate_reaching_the_target():
    script = _script("choose_real_world_threshold")
    suggestions = ([{"document": "a", "score": 0.3, "cited_parent": False}] * 6
                   + [{"document": "a", "score": 0.6, "cited_parent": True}] * 3
                   + [{"document": "b", "score": 0.9, "cited_parent": True}] * 3)
    rows = [script.at_threshold(suggestions, t) for t in script.CANDIDATES]
    assert [(r["kept"], r["agree"]) for r in rows] == [(12, 6), (6, 6), (3, 3)]
    assert rows[0]["documents_with_suggestions"] == 2
    assert script.choose(rows) == 0.25  # 6/12 = 0.5 reaches the target exactly
    assert script.choose(rows, target=0.51) == 0.5
    none = [script.at_threshold(suggestions[:6], t) for t in script.CANDIDATES]
    assert none[1]["agreement"] is None and script.choose(none) is None


def test_wilson_interval():
    script = _script("choose_real_world_threshold")
    low, high = script.wilson(10, 17)
    assert round(low, 2) == 0.36 and round(high, 2) == 0.78
    assert script.wilson(0, 0) is None
    low, high = script.wilson(0, 5)
    assert low == pytest.approx(0, abs=1e-12) and 0 < high < 0.5


def test_threshold_selection_needs_a_split_manifest(tmp_path, monkeypatch):
    import json

    script = _script("choose_real_world_threshold")
    path = tmp_path / "m.json"
    path.write_text(json.dumps({"documents": []}))
    monkeypatch.setattr("sys.argv", ["x", "--manifest", str(path)])
    with pytest.raises(SystemExit, match="no development split"):
        script.main()
