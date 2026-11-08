FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src ./src
COPY mocks ./mocks
COPY config.json ./config.json
COPY scenarios.json ./scenarios.json
ENV TWIN_HOST=0.0.0.0 PYTHONUNBUFFERED=1
# Keys are never in the image. Mount secrets.json at /app/secrets.json (see ../docker-compose.yml).
EXPOSE 8080
CMD ["python", "src/twin.py", "serve"]
