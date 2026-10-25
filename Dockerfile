# One image for the Python services (gateway, audit, later: control, signer, workers).
# Each service picks its entrypoint with `command:` in compose.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Fixed non-root user. /data is created and owned here so a fresh named volume
# mounted at /data inherits the right owner.
RUN useradd --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin sentinel \
    && mkdir -p /data /audit /checkpoints && chown 10001:10001 /data /audit /checkpoints

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY sentinel/ sentinel/

USER 10001
