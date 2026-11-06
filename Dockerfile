FROM node:20-bookworm-slim

WORKDIR /app
COPY keyserver ./keyserver
COPY web ./web
COPY content ./content

# Cloud (free-tier) rejim: MinIO'siz — app shifrlangan segmentlarni o'zi beradi.
# Himoya o'zgarmas: login/session, token-gated /key, manifest token-gated, 403 deny.
ENV NO_MINIO=1
ENV PUBLIC=1
ENV PORT=8000

EXPOSE 8000
CMD ["node", "keyserver/app.js"]
