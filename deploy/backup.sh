#!/usr/bin/env bash
# Sauvegarde cohérente de la base QROOD (compatible WAL) via `VACUUM INTO`.
# À planifier chaque nuit :  crontab -e →  0 3 * * * /opt/qrood/deploy/backup.sh
set -euo pipefail

DATA_DIR="${QROOD_DATA_DIR:-/opt/qrood/data}"
BACKUP_DIR="${QROOD_BACKUP_DIR:-/root/backups/qrood}"
STAMP="$(date +%F-%H%M%S)"

mkdir -p "$BACKUP_DIR"
cd "$DATA_DIR"

node -e '
  const { DatabaseSync } = require("node:sqlite");
  const source = process.argv[1];
  const dest = process.argv[2];
  const db = new DatabaseSync(source);
  try {
    db.exec(`VACUUM INTO ${JSON.stringify(dest)}`);
  } finally {
    db.close();
  }
' "$DATA_DIR/qrood.sqlite" "$BACKUP_DIR/qrood-$STAMP.sqlite"

# Ne conserver que les 14 dernières sauvegardes.
ls -1t "$BACKUP_DIR"/qrood-*.sqlite | tail -n +15 | xargs -r rm -f

echo "Sauvegarde : $BACKUP_DIR/qrood-$STAMP.sqlite"