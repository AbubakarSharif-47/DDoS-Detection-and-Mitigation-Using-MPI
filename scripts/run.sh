#!/usr/bin/env sh
# scripts/run.sh
# Normalize CSV, build, run mpirun and evaluate (POSIX / Linux helper)
set -e

CSV="$1"
PROCS="${2:-4}"
PYTHON=python3

if [ -z "$CSV" ]; then
    echo "Usage: $0 path/to/input.csv [procs]"
    exit 1
fi

echo "[run] Normalizing input CSV: $CSV"
$PYTHON scripts/to_flows.py "$CSV"

NAME=$(basename "$CSV" .csv)
OFF="data/${NAME}_offline.csv"

if [ ! -f "$OFF" ]; then
    echo "Normalized file not found: $OFF"
    exit 1
fi

echo "[run] Building project"
make

echo "[run] Running MPI program with $PROCS processes"
mpirun -np "$PROCS" ./pdc "$OFF"

echo "[run] Running evaluation"
$PYTHON ./python/evaluate.py "$OFF"

echo "[run] Done"
