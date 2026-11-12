"""Static checks of the container files (Docker isn't available in the test environment)."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
IGNORE = {line.strip() for line in (ROOT / ".dockerignore").read_text(encoding="utf-8")
          .splitlines() if line.strip() and not line.startswith("#")}


def test_base_image_is_pinned():
    (image,) = re.findall(r"^FROM\s+(\S+)", DOCKERFILE, re.MULTILINE)
    assert re.fullmatch(r"python:3\.12\.\d+-slim-\w+", image), image


def test_runs_as_an_unprivileged_user():
    users = re.findall(r"^USER\s+(\S+)", DOCKERFILE, re.MULTILINE)
    assert users and users[-1] not in {"root", "0"}
    assert DOCKERFILE.index("USER ") < DOCKERFILE.index("CMD [")


def test_health_check_and_server_command():
    assert "HEALTHCHECK" in DOCKERFILE and "127.0.0.1:8000/healthz" in DOCKERFILE
    assert 'CMD ["python", "-m", "src.web", "--host", "0.0.0.0", "--port", "8000"]' in DOCKERFILE
    assert "EXPOSE 8000" in DOCKERFILE


def test_health_endpoint_exists():
    from fastapi.testclient import TestClient

    from src.web.app import create_app

    client = TestClient(create_app(lambda: None, lambda: None))
    assert client.get("/healthz").json() == {"status": "ok"}


def test_models_are_fetched_with_hash_checks():
    assert "scripts/fetch_models.py" in DOCKERFILE and "FETCH_MODELS" in DOCKERFILE


def test_copied_files_exist():
    for line in re.findall(r"^COPY\s+(.+)$", DOCKERFILE, re.MULTILINE):
        *sources, _target = line.split()
        for source in sources:
            if source != ".":
                assert (ROOT / source).exists(), source


def test_secrets_and_local_data_stay_out_of_the_image():
    for pattern in (".git", ".venv", ".env", "*.db", "data/raw"):
        assert pattern in IGNORE, pattern
    # the knowledge bases and samples the app needs must not be excluded
    assert not {"data", "data/knowledge_base", "data/samples", "config", "src"} & IGNORE


def test_database_lives_outside_the_app_tree():
    assert "CYBERSLEUTH_DB_URL=sqlite:////var/lib/cybersleuth/" in DOCKERFILE
    assert 'VOLUME ["/var/lib/cybersleuth"]' in DOCKERFILE
