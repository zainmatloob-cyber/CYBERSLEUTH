"""scripts/fetch_models.py: only files matching the pinned SHA-256 reach models/.

No network: the downloader is replaced by an in-memory fake.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def script():
    spec = importlib.util.spec_from_file_location("fetch_models",
                                                  ROOT / "scripts" / "fetch_models.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GOOD = b"trusted model bytes"


def _config(data: bytes = GOOD) -> dict:
    return {"repository": "owner/repo", "release_tag": "models-v1",
            "files": {"m.joblib": {"sha256": hashlib.sha256(data).hexdigest(),
                                   "bytes": len(data)}}}


def _opener(payload: bytes, seen: list):
    def open_url(url, timeout):
        seen.append(url)
        return io.BytesIO(payload)
    return open_url


def test_downloads_and_installs_a_matching_file(script, tmp_path):
    seen = []
    assert script.fetch(_config(), tmp_path, opener=_opener(GOOD, seen)) == []
    assert (tmp_path / "m.joblib").read_bytes() == GOOD
    assert seen == ["https://github.com/owner/repo/releases/download/models-v1/m.joblib"]
    assert not list(tmp_path.glob("*.part"))
    seen.clear()  # already up to date: nothing is downloaded again
    assert script.fetch(_config(), tmp_path, opener=_opener(GOOD, seen)) == [] and not seen


def test_a_tampered_file_is_deleted_not_installed(script, tmp_path):
    problems = script.fetch(_config(), tmp_path, opener=_opener(b"evil model bytes!!", []))
    assert problems and "SHA-256 does not match" in problems[0]
    assert not (tmp_path / "m.joblib").exists() and not list(tmp_path.glob("*.part"))


def test_an_oversized_download_is_cut_off(script, tmp_path):
    problems = script.fetch(_config(), tmp_path, opener=_opener(GOOD + b"x" * 5_000_000, []))
    assert problems and "larger than the expected" in problems[0]
    assert not (tmp_path / "m.joblib").exists()


def test_a_wrong_local_file_is_replaced(script, tmp_path):
    (tmp_path / "m.joblib").write_bytes(b"stale")
    assert script.fetch(_config(), tmp_path, opener=_opener(GOOD, [])) == []
    assert (tmp_path / "m.joblib").read_bytes() == GOOD


def test_verify_only_never_downloads(script, tmp_path):
    seen = []
    problems = script.fetch(_config(), tmp_path, verify_only=True, opener=_opener(GOOD, seen))
    assert problems == ["m.joblib: missing"] and not seen


def test_plain_http_is_refused(script, tmp_path):
    with pytest.raises(ValueError, match="non-HTTPS"):
        script.download("http://example.org/m", tmp_path / "m", 10)


def test_pinned_hashes_match_the_shipped_config(script):
    config = json.loads((ROOT / "config" / "model_files.json").read_text(encoding="utf-8"))
    assert set(config["files"]) == {"technique_model.joblib", "threat_classifier.joblib"}
    for spec in config["files"].values():
        assert len(spec["sha256"]) == 64 and spec["bytes"] > 0
    local = ROOT / "models" / "technique_model.joblib"
    if local.exists():  # the evaluated model on a development machine
        assert script.sha256(local) == config["files"]["technique_model.joblib"]["sha256"]
