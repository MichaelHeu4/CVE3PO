FROM rust:1.87-slim AS agent-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    musl-tools \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/software-agent
COPY software-agent/Cargo.toml software-agent/Cargo.lock ./
COPY software-agent/src ./src

RUN rustup target add x86_64-unknown-linux-musl
RUN cargo build --release --target x86_64-unknown-linux-musl
RUN mkdir -p /out \
    && cp /build/software-agent/target/x86_64-unknown-linux-musl/release/software-agent /out/cve3po-agent-linux-amd64 \
    && chmod +x /out/cve3po-agent-linux-amd64 \
    && sha256sum /out/cve3po-agent-linux-amd64 | awk '{print $1 "  cve3po-agent-linux-amd64"}' > /out/cve3po-agent-linux-amd64.sha256

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
COPY --from=agent-builder /out/cve3po-agent-linux-amd64 /app/software-agent/cve3po-agent-linux-amd64
COPY --from=agent-builder /out/cve3po-agent-linux-amd64.sha256 /app/software-agent/cve3po-agent-linux-amd64.sha256

RUN chmod +x /app/entrypoint.sh

USER appuser

EXPOSE 8000
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "cve3po.wsgi:application"]
