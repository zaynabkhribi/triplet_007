# AEGIS LOOP — Guardian container image.
# Self-contained: the Guardian reads the city from the Orion broker and serves
# its verdict feed on 8090, so the container needs no partner mount at all.
FROM python:3.11-slim

WORKDIR /app
ENV PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1 \
    GUARDIAN_PORT=8090

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
# keys/dev_keys.json is the DEV keyring: without it every device resolves to
# UNKNOWN_DEVICE and every scenario fails inside the container. It holds only
# synthetic per-device secrets for the simulated city (real keys come from
# GUARDIAN_HMAC_KEY / the environment and are never committed).
COPY keys/ ./keys/
COPY config.yaml policy.yaml sensor_profiles.yaml ngsi.yaml orion_devices.json ./
COPY static/ ./static/
COPY shared/ ./shared/

EXPOSE 8090
# Defaults come from config.yaml: orion.enabled=true, so the process starts the
# poller and fills /verdicts from the broker with no partner intervention.
CMD ["python", "-m", "guardian", "--host", "0.0.0.0", "--port", "8090"]
