# Deployment

Three ways to run CyberSleuth. All of them run the same app, and the app makes no outbound
network requests. Before exposing it to anyone else, read
[security.md § Deployment limits](security.md#deployment-limits): the app has **no login**.

## 1. Local (development)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt -c requirements.lock.txt
python scripts/fetch_models.py      # trained models, SHA-256 verified (see below)
streamlit run app.py
```

* **Without the models,** the app still runs. Threat categories come from rules only, ATT&CK
  mapping uses explicit matches only, and the app shows a warning.
* **Without the spaCy model,** organisation and location recognition are off; knowledge-base
  and pattern rules still run.

## 2. Docker

> **Status: written but not yet built or run.** Docker wasn't available on the development
> machine. What has been checked:
> * the start command and health-check path, by running Streamlit locally with the same
>   flags (`/_stcore/health` answered `200 ok`);
> * the Dockerfile's structure, by static tests (`tests/test_deployment.py`): pinned base
>   image, non-root user, health check, ignored secrets, copied files exist.
>
> The first real build may still need small fixes.

```bash
docker build -t cybersleuth .
docker run --rm -p 8501:8501 --memory 1g --cpus 2 \
  -v cybersleuth-db:/var/lib/cybersleuth cybersleuth
```

Then open <http://localhost:8501>.

* **Image:** `python:3.12.10-slim-bookworm`. Every dependency version is constrained by
  `requirements.lock.txt`.
* **Models** are downloaded during the build from the GitHub release and checked against
  `config/model_files.json`. A wrong file fails the build. Build with
  `--build-arg FETCH_MODELS=0` for a rules-only image.
* **Runs as an unprivileged user** (uid 10001). The only writable path is the database volume
  `/var/lib/cybersleuth`.
* **Health check:** `/_stcore/health`.
* **Memory:** the models take about 354 MB and one analysis adds about 75 MB per million
  characters ([performance.md](performance.md)), so 1 GB leaves headroom.
* **Network:** the running container needs no outbound access. Where the platform allows it,
  run it with outbound traffic blocked, for example on a Docker network without internet
  access. The build itself needs internet access for pip and the model download.
* **Secrets:** `.dockerignore` keeps `.env`, `.streamlit/secrets.toml`, local databases and
  downloaded data out of the image.

## 3. Streamlit Community Cloud

Point a new app at this repository, with `app.py` as the entry point and Python 3.12 under
*Advanced settings*. `requirements.txt` installs everything, including the spaCy model from
its pinned URL.

Caveats:
* **The trained models aren't in the repository,** and the app never downloads anything
  itself. A Cloud deployment therefore runs without them (rules-only categories,
  explicit-only ATT&CK mapping) and says so. To use the models there, they would need to be
  committed with Git LFS; that hasn't been set up.
* **The file system is temporary.** The SQLite database is lost when the app restarts, so
  history, verdicts and the dashboard reset.
* **No login.** A public Cloud app can be used by anyone, and they all share one database.
  Make the app private, restricted to invited viewers, and upload public documents only.
* **Resources:** check the platform's current memory limit against the figures above.

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
