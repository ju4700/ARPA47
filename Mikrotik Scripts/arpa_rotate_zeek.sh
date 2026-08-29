#!/bin/bash
# arpa_rotate_zeek.sh - Fixed: uses sudo truncate for cron jobs
LOG_DIR="/data/arpa/zeek_logs"
ARCHIVE_DIR="/data/arpa/zeek_archive"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SLOT=$(date +%Y%m%d_%H)

mkdir -p "$ARCHIVE_DIR/$SLOT"

cd "$LOG_DIR" || exit 1

for f in *.log; do
    [ -f "$f" ] || continue
    ARCHIVE_PATH="$ARCHIVE_DIR/$SLOT/${f%.log}_${TIMESTAMP}.log.gz"
    
    # Skip if already archived this slot (idempotent)
    if ls "$ARCHIVE_DIR/$SLOT/${f%.log}_"*.log.gz &>/dev/null 2>&1; then
        echo "[$(date)] Skipping $f (already archived this slot)"
        continue
    fi

    echo "[$(date)] Archiving $f -> $ARCHIVE_PATH"
    gzip -c "$f" > "$ARCHIVE_PATH"

    # Truncate with sudo so the ju4700 cron job can empty root-owned files
    if sudo truncate -s 0 "$f" 2>/dev/null; then
        echo "[$(date)] Truncated $f (sudo direct)"
    else
        echo "[$(date)] WARNING: Could not truncate $f (permission denied)"
    fi
done

echo "[$(date)] Rotation complete. Archive: $ARCHIVE_DIR/$SLOT"

USED_PCT=$(df /data --output=pcent | tail -1 | tr -d ' %')
if [ "$USED_PCT" -gt 80 ]; then
    echo "[$(date)] WARNING: /data is ${USED_PCT}% full!"
fi
