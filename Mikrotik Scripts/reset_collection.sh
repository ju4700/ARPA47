#!/bin/bash
systemctl stop arpa-zeek arpa-nfcapd arpa-tzsp-decapper
rm -rf /data/arpa/zeek_logs/*
rm -rf /data/arpa/zeek_archive/*
rm -rf /data/arpa/netflow/*
echo "Logs wiped. Waiting until 18:00..."

current_epoch=$(date +%s)
target_epoch=$(date -d "today 18:00:00" +%s)

if [ "$current_epoch" -lt "$target_epoch" ]; then
  sleep_time=$((target_epoch - current_epoch))
  sleep $sleep_time
fi

systemctl start arpa-tzsp-decapper arpa-zeek arpa-nfcapd
echo "Services started at 18:00."
