#!/bin/bash
# collect_stats.sh duration_seconds interval_seconds
DURATION=${1:-60}
INTERVAL=${2:-1}
OUTDIR="output/metrics"
mkdir -p "$OUTDIR"
OUT="$OUTDIR/sys_stats.csv"
echo "timestamp,cpu_idle,cpu_usr,mem_free,net_rx,net_tx" > "$OUT"
END=$((SECONDS + DURATION))
while [ $SECONDS -lt $END ]; do
  TS=$(date +%s.%N)
  # CPU via mpstat (all)
  MP=$(mpstat 1 1 | awk '/all/ {print $3","$4}')
  CPU_IDLE=$(echo $MP | cut -d, -f1)
  CPU_USR=$(echo $MP | cut -d, -f2)
  MEM_FREE=$(free -m | awk '/Mem:/ {print $4}')
  # network bytes (eth0)
  RX=$(cat /proc/net/dev | awk '/eth0/ {print $2}')
  TX=$(cat /proc/net/dev | awk '/eth0/ {print $10}')
  echo "$TS,$CPU_IDLE,$CPU_USR,$MEM_FREE,$RX,$TX" >> "$OUT"
  sleep $INTERVAL
done
echo "Saved $OUT"
