#!/usr/bin/env sh
# scripts/run_local.sh
# Create a small sample, normalize it, build, run with 1 process, then evaluate and plot.
set -e

IN=$1
if [ -z "$IN" ]; then
    echo "Usage: $0 data/Portmap.csv"
    exit 1
fi

echo "[run_local] Extracting first 100 rows"
python3 data/first100.py "$IN"

BASE=$(basename "$IN" .csv)
SAMP="${BASE}_first100.csv"

echo "[run_local] Normalizing sample"
python3 scripts/to_flows.py "$SAMP"

NAME=$(basename "$SAMP" .csv)
OFF="data/${NAME}_offline.csv"

echo "[run_local] Building"
make

echo "[run_local] Running pdc (single process)"
mpirun -np 1 ./pdc "$OFF"

echo "[run_local] Evaluating and plotting"
python3 python/evaluate.py "$OFF" --debug
python3 python/plot_metrics.py output/evaluation_metrics.csv

echo "[run_local] Done. Check output/ for reports and plots."
