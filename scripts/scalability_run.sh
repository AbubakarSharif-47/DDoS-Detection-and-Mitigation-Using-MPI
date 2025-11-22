#!/bin/bash
FLOW=${1:-data/flows_sample.csv}
HOSTFILE=${2:-hostfile}
OUT="output/metrics/scalability.csv"
echo "nodes,run_time_s,pps,gbps" > $OUT
for N in 2 4 8; do
  START=$(date +%s.%N)
  mpirun --hostfile $HOSTFILE -np $N ./pdc $FLOW
  END=$(date +%s.%N)
  RUN=$(echo "$END - $START" | bc)
  # quick metrics using evaluate.py then parse printed JSON (we'll call evaluate in quick mode)
  python3 python/evaluate.py --mode offline --flowfile $FLOW --results output/results.txt --quick > /dev/null
  # evaluate.py writes JSON to output/metrics/tmp_eval.json
  PPS=$(jq -r '.pps' output/metrics/tmp_eval.json)
  GBPS=$(jq -r '.gbps' output/metrics/tmp_eval.json)
  echo "$N,$RUN,$PPS,$GBPS" >> $OUT
done
echo "Scalability results -> $OUT"
