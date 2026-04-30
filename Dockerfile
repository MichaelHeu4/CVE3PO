FROM python:3.13-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    libcairo2-dev \
    pkg-config \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir /app
WORKDIR /app
RUN pip install --upgrade pip
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libcairo2 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -r appuser && mkdir /app && chown -R appuser /app

COPY --from=builder /usr/local/lib/python3.13/site-packages/ /usr/local/lib/python3.13/site-packages/
COPY --from=builder /usr/local/bin/ /usr/local/bin/

WORKDIR /app
RUN mkdir -p /app/data && chown -R appuser:appuser /app/data
COPY --chown=appuser:appuser . .

USER appuser

EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "cve3po.wsgi:application"]

