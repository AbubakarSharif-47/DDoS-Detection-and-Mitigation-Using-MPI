#!/bin/bash
OUT="output/gpu_usage.csv"
echo "ts,utilization.gpu [%]" > $OUT
INTERVAL=${1:-1}
DURATION=${2:-60}
END=$((SECONDS + DURATION))
while [ $SECONDS -lt $END ]; do
  TS=$(date +%s.%N)
  UTIL=$(nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits 2>/dev/null || echo "0")
  echo "$TS,$UTIL" >> $OUT
  sleep $INTERVAL
done
echo "Saved $OUT"
