FROM node:20-bookworm-slim

# curl + ca-certificates (MinIO health + yuklab olish uchun)
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# MinIO server + mc client (linux amd64) — HF konteyneri ichida obyekt-saqlash
RUN curl -fsSL https://dl.min.io/server/minio/release/linux-amd64/minio -o /usr/local/bin/minio \
    && curl -fsSL https://dl.min.io/client/mc/release/linux-amd64/mc -o /usr/local/bin/mc \
    && chmod +x /usr/local/bin/minio /usr/local/bin/mc

WORKDIR /app
COPY keyserver ./keyserver
COPY web ./web
COPY content ./content
COPY start.sh ./start.sh
RUN chmod +x ./start.sh \
    && mkdir -p /app/minio-data \
    && chmod -R 777 /app/minio-data /app/content

# HF Space app_port bilan mos (README: app_port: 8000)
ENV PORT=8000
EXPOSE 8000

CMD ["./start.sh"]
