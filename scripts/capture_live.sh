#!/bin/bash
# capture_live.sh: capture packets to data/live_raw.csv
IFACE=${1:-eth0}
OUT="data/live_raw.csv"
echo "Capturing on $IFACE -> $OUT (Ctrl-C to stop)"
sudo tshark -i "$IFACE" -T fields -e frame.time_epoch -e ip.src -e frame.len -E separator=, > "$OUT"

