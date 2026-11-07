"""Tests for the threat-category dataset builder (src/ml/dataset.py)."""

from __future__ import annotations

import pandas as pd
import pytest

from src.ml.dataset import (
    OTHER,
    DatasetError,
    GroupKeyer,
    assign_split,
    build_dataset,
    clean_text,
    dataset_statistics,
    load_category_map,
    parent_technique,
    technique_from_label,
    verify_raw_file,
)


@pytest.fixture(scope="module")
def category_map():
    return load_category_map()


@pytest.fixture(scope="module")
def keyer():
    return GroupKeyer()


# --- category map -------------------------------------------------------------


def test_category_map_loads(category_map):
    assert set(category_map.categories) == {
        "phishing", "ransomware", "vulnerability_exploitation", "credential_theft",
        "data_breach", "ddos",
    }


@pytest.mark.parametrize(
    ("techniques", "expected"),
    [
        (["T1566.001"], {"phishing"}),  # sub-technique inherits parent
        (["T1486"], {"ransomware"}),
        (["T1212"], {"credential_theft", "vulnerability_exploitation"}),  # one → many
        (["T1566.002", "T1041"], {"phishing", "data_breach"}),  # many → union
        (["T1059.001"], {OTHER}),
        ([], {OTHER}),
    ],
)
def test_categorize(category_map, techniques, expected):
    assert category_map.categorize(techniques) == frozenset(expected)


def test_invalid_map_entry_rejected(tmp_path):
    path = tmp_path / "map.json"
    path.write_text('{"version": "x", "categories": {"bad": {"techniques": ["T15"]}}}',
                    encoding="utf-8")
    with pytest.raises(DatasetError):
        load_category_map(path)


# --- parsing and cleaning -----------------------------------------------------


@pytest.mark.parametrize(
    ("label", "technique"),
    [("T1562.001: Impair Defenses- Disable or Modify Tools", "T1562.001"),
     ("T1133: External Remote Services", "T1133")],
)
def test_technique_from_label(label, technique):
    assert technique_from_label(label) == technique
    assert parent_technique(technique) == technique[:5]


@pytest.mark.parametrize("bad", ["Impair Defenses", "T12: x", ""])
def test_bad_labels_rejected(bad):
    with pytest.raises(DatasetError):
        technique_from_label(bad)


def test_clean_text_removes_markup():
    raw = "Elise executes <code>net user</code>  after login.(Citation: Vendor 2020)"
    assert clean_text(raw) == "Elise executes net user after login."


# --- grouping and splitting ---------------------------------------------------


@pytest.mark.parametrize(
    ("text", "group"),
    [
        ("APT28 has used spearphishing.", "attack:G0007"),
        ("Fancy Bear has used spearphishing.", "attack:G0007"),  # alias → same group
        ("Lazarus Group used a backdoor.", "attack:G0032"),
        ("During C0027, Scattered Spider downloaded tools.", "attack:G1015"),  # actor wins
        ("During Operation Nowhere, the actors used RDP.", "campaign:operation nowhere"),
        ("A gh0st RAT variant has used DLL side-loading.", "attack:S0032"),
        ("Unknownware has used PowerShell.", "subject:unknownware"),
    ],
)
def test_group_keys(keyer, text, group):
    assert keyer.key(text) == group


def test_split_assignment_is_deterministic_and_balanced():
    assert assign_split("attack:G0007") == assign_split("attack:G0007")
    splits = pd.Series([assign_split(f"group-{i}") for i in range(3000)]).value_counts(
        normalize=True)
    assert splits["train"] == pytest.approx(0.70, abs=0.04)
    assert splits["val"] == pytest.approx(0.15, abs=0.04)
    assert splits["test"] == pytest.approx(0.15, abs=0.04)


# --- building -----------------------------------------------------------------


def _raw() -> pd.DataFrame:
    return pd.DataFrame({
        "text": [
            "APT28 has used spearphishing emails.",
            "APT28 has used spearphishing emails.",  # same text, second technique
            "Emotet can dump credentials with <code>mimikatz</code>.",
            "Emotet uses PowerShell.",
            "Fancy Bear exfiltrated data over C2.",
        ],
        "label": [
            "T1566.001: Phishing- Spearphishing Attachment",
            "T1598.002: Phishing for Information- Spearphishing Attachment",
            "T1003: OS Credential Dumping",
            "T1059.001: Command and Scripting Interpreter- PowerShell",
            "T1041: Exfiltration Over C2 Channel",
        ],
    })


def test_build_dataset(category_map, keyer):
    data = build_dataset(_raw(), category_map, keyer).set_index("text")
    assert len(data) == 4  # duplicate text merged
    assert data.loc["APT28 has used spearphishing emails.", "techniques"] == (
        "T1566.001", "T1598.002")
    assert data.loc["Emotet can dump credentials with mimikatz.", "categories"] == (
        "credential_theft",)
    assert data.loc["Emotet uses PowerShell.", "categories"] == (OTHER,)
    # Alias rows share a group and therefore a split.
    apt28 = data.loc[["APT28 has used spearphishing emails.",
                      "Fancy Bear exfiltrated data over C2."]]
    assert apt28["group"].nunique() == 1 and apt28["split"].nunique() == 1


def test_build_dataset_rejects_wrong_columns(category_map):
    with pytest.raises(DatasetError):
        build_dataset(pd.DataFrame({"sentence": ["x"]}), category_map)


def test_statistics_report_no_group_leakage(category_map, keyer):
    stats = dataset_statistics(build_dataset(_raw(), category_map, keyer),
                               category_map.categories)
    assert stats["groups_in_multiple_splits"] == 0
    assert stats["sentences"] == 4 and stats["multi_technique_sentences"] == 1


# --- raw file verification ----------------------------------------------------


def test_verify_raw_file(tmp_path):
    path = tmp_path / "dataset.csv"
    with pytest.raises(DatasetError, match="not found"):
        verify_raw_file(path)
    path.write_bytes(b"text,label\n")
    with pytest.raises(DatasetError, match="mismatch"):
        verify_raw_file(path)
    import hashlib

    verify_raw_file(path, hashlib.sha256(b"text,label\n").hexdigest())
