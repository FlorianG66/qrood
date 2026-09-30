#!/usr/bin/env bash
set -e
cd ~/qraft
git pull
docker compose up -d --build
docker compose logs --tail 20