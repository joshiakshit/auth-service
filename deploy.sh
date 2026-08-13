#!/bin/bash
set -euo pipefail

APP_DIR="/opt/services"
IMAGE_TAG="${1:-latest}"

cd "$APP_DIR"

docker compose -f docker-compose.prod.yml pull auth-service

docker compose -f docker-compose.prod.yml run --rm auth-service \
    alembic upgrade head

docker compose -f docker-compose.prod.yml up -d --no-deps auth-service

docker compose -f docker-compose.prod.yml restart nginx

docker image prune -f

echo "Deploy complete"
