#!/bin/bash
# usage: ./replay_pcap.sh <pcapfile> <iface> <pps_or_mbps>
PCAP=$1
IFACE=${2:-eth0}
RATE=${3:-1000}   # pps when using --pps (or use --mbps option with tcpreplay)
if [ -z "$PCAP" ]; then echo "Usage: $0 file.pcap iface [pps]"; exit 1; fi
sudo tcpreplay --intf1="$IFACE" --pps="$RATE" "$PCAP"
