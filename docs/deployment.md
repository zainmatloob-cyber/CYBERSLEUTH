# Deployment

Ways to run CyberSleuth. All of them run the same app, and the app makes no outbound
network requests. Before exposing it to anyone else, read
[security.md § Deployment limits](security.md#deployment-limits): the app has **no login**.

## 1. Local (development)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt -c requirements.lock.txt
python scripts/fetch_models.py      # trained models, SHA-256 verified (see below)
python -m src.web                   # http://127.0.0.1:8000
```

* **Without the models,** the app still runs. Threat categories come from rules only, ATT&CK
  mapping uses explicit matches only, and the app shows a warning.
* **Without the spaCy model,** organisation and location recognition are off; knowledge-base
  and pattern rules still run.

## 2. Docker

> **Status: written but not yet built or run.** Docker wasn't available on the development
> machine. What has been checked:
> * the start command and health-check path, by running `python -m src.web --host 0.0.0.0
>   --port 8000` locally (`/healthz` answered `{"status": "ok"}`);
> * the Dockerfile's structure, by static tests (`tests/test_deployment.py`): pinned base
>   image, non-root user, health check, ignored secrets, copied files exist.
>
> The first real build may still need small fixes.

```bash
docker build -t cybersleuth .
docker run --rm -p 127.0.0.1:8000:8000 --memory 1g --cpus 2 \
  -v cybersleuth-db:/var/lib/cybersleuth cybersleuth
```

Then open <http://localhost:8000>. `127.0.0.1:` in `-p` publishes the port on this machine
only; the server inside the container must listen on `0.0.0.0` for publishing to work.

* **Image:** `python:3.12.10-slim-bookworm`. Every dependency version is constrained by
  `requirements.lock.txt`.
* **Models** are downloaded during the build from the GitHub release and checked against
  `config/model_files.json`. A wrong file fails the build. Build with
  `--build-arg FETCH_MODELS=0` for a rules-only image.
* **Runs as an unprivileged user** (uid 10001). The only writable path is the database volume
  `/var/lib/cybersleuth`.
* **Health check:** `/healthz`.
* **Memory:** the models take about 354 MB and one analysis adds about 75 MB per million
  characters ([performance.md](performance.md)), so 1 GB leaves headroom.
* **Network:** the running container needs no outbound access. Where the platform allows it,
  run it with outbound traffic blocked, for example on a Docker network without internet
  access. The build itself needs internet access for pip and the model download.
* **Secrets:** `.dockerignore` keeps `.env`, local databases and
  downloaded data out of the image.

## 3. Behind a reverse proxy (shared use)

The app has no login, so it binds to `127.0.0.1` by default. To share it with a team, keep it
on localhost (or a private container network) and put a reverse proxy in front that:

* **authenticates** every request (for example basic auth or single sign-on);
* terminates **TLS**;
* forwards to `http://127.0.0.1:8000` and passes the `Host` header through unchanged.

The app already refuses cross-site POSTs (it checks the `Sec-Fetch-Site` and `Origin`
headers) and request bodies larger than the upload limit plus 1 MB, so the proxy needs no
extra configuration for those. Everyone who gets past the proxy shares one database and can
change verdicts or delete documents.

## Publishing the model files (one-time, by the repository owner)

`scripts/fetch_models.py` downloads from the release `models-v1`. To create it:

1. On GitHub, open **Releases → Draft a new release**.
2. Create the tag `models-v1` on `main`.
3. Attach `models/technique_model.joblib` and `models/threat_classifier.joblib` from the
   machine that ran the evaluations.
4. Publish.
5. Check: `python scripts/fetch_models.py --verify` on that machine reports `OK` for both
   files. On a fresh clone, `python scripts/fetch_models.py` should download and verify them.

The expected SHA-256 values are in `config/model_files.json`:

| File | Size | SHA-256 |
|---|---|---|
| `technique_model.joblib` | 77,174,226 bytes | `43fb9db6…abda46` |
| `threat_classifier.joblib` | 2,949,538 bytes | `408e9289…dc41a159` |

These are exactly the files behind every recorded result. If the models are ever retrained,
publish a new release tag and update the config in the same commit. Retraining with
`--final` also re-scores the held-out test split, so don't do it casually.
