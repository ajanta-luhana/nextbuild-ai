FROM python:3.12-slim
RUN useradd --create-home --uid 10001 app && apt-get update && apt-get install -y --no-install-recommends util-linux && rm -rf /var/lib/apt/lists/*
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY autoforge ./autoforge
RUN mkdir -p /var/lib/autoforge && chown app /var/lib/autoforge
USER app
ENV HOST=0.0.0.0 PORT=8000 DATABASE_PATH=/var/lib/autoforge/autoforge.db ARTIFACT_ROOT=/var/lib/autoforge/artifacts WORKSPACE_ROOT=/var/lib/autoforge/workspaces
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/api/v1/health/live', timeout=2)"
CMD ["python", "-m", "autoforge.api.app"]
