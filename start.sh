#!/usr/bin/env bash
set -e

export PORT=${PORT:-8000}
export PUBLIC=1

if [ "${NO_MINIO}" = "1" ]; then
  # RAM-cheklangan host: MinIO yo'q, app segmentlarni local fs'dan beradi
  echo "NO_MINIO rejimi: app segmentlarni o'zi beradi"
  export PUBLIC_PROXY=0
  echo "App ishga tushyapti :$PORT (NO_MINIO)"
  exec node keyserver/app.js
fi

# ===== To'liq rejim: MinIO obyekt-saqlash + app proxy =====
export MINIO_ROOT_USER=minioadmin
export MINIO_ROOT_PASSWORD=minioadmin
export MINIO_API_CORS_ALLOW_ORIGIN="*"
minio server /app/minio-data --address :9000 --console-address :9001 &

echo "MinIO kutilmoqda..."
for i in $(seq 1 60); do
  if curl -sf http://localhost:9000/minio/health/live >/dev/null; then echo "MinIO tayyor"; break; fi
  sleep 1
done

mc alias set lab http://localhost:9000 minioadmin minioadmin
mc mb -p lab/videos || true
mc mirror --overwrite /app/content/hls lab/videos/hls
echo "Seed tugadi:"; mc ls --recursive lab/videos || true

export PUBLIC_PROXY=1
echo "App ishga tushyapti :$PORT (MinIO proxy)"
exec node keyserver/app.js
