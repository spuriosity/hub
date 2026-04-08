FROM python:3.13-slim

WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir \
    "fastapi>=0.115" \
    "uvicorn[standard]>=0.34" \
    "jinja2>=3.1" \
    "itsdangerous>=2.2" \
    "httpx>=0.28" \
    "pyyaml>=6.0" \
    "python-multipart>=0.0.18"
COPY . .

ENV GATE_CONFIG=/etc/gate/config.yaml

EXPOSE 8090
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8090"]
