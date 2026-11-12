# CyberSleuth container image. See docs/deployment.md.
#
#   docker build -t cybersleuth .
#   docker run --rm -p 127.0.0.1:8000:8000 --memory 1g -v cybersleuth-db:/var/lib/cybersleuth cybersleuth
#
# The app has no login: publish the port on localhost only, or put an authenticating
# reverse proxy in front of it (docs/deployment.md).
#
# Build without the trained models (rules-only analysis, the app says so):
#   docker build --build-arg FETCH_MODELS=0 -t cybersleuth .

FROM python:3.12.10-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies first, so code changes don't reinstall them. requirements.lock.txt pins
# every version as a constraint; pip doesn't accept URL lines as constraints, so the spaCy
# model line is removed from the constraint copy (requirements.txt pins its URL).
COPY requirements.txt requirements.lock.txt ./
RUN grep -v "en_core_web_sm @" requirements.lock.txt > /tmp/constraints.txt \
    && pip install -r requirements.txt -c /tmp/constraints.txt \
    && rm /tmp/constraints.txt

COPY . .

# Trained models: downloaded from the GitHub release and checked against the SHA-256
# values in config/model_files.json. Files already in models/ with the right hash are kept.
ARG FETCH_MODELS=1
RUN if [ "$FETCH_MODELS" = "1" ]; then python scripts/fetch_models.py; fi

# Run as an unprivileged user. Only the database directory is writable.
RUN useradd --create-home --uid 10001 cybersleuth \
    && mkdir -p /var/lib/cybersleuth \
    && chown cybersleuth /var/lib/cybersleuth
USER cybersleuth

ENV CYBERSLEUTH_DB_URL=sqlite:////var/lib/cybersleuth/cybersleuth.db
VOLUME ["/var/lib/cybersleuth"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)"

# 0.0.0.0 inside the container is required for port publishing; see the docker run note.
CMD ["python", "-m", "src.web", "--host", "0.0.0.0", "--port", "8000"]
