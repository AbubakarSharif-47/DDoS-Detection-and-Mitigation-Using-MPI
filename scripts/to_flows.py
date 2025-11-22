#!/usr/bin/env python3
"""
scripts/to_flows.py
Normalize any CSV to canonical offline flow CSV with LOWERCASE columns:
timestamp, src_ip, src_port, dst_ip, dst_port, protocol, duration, packets, label

These lowercase headers are fuzzy-matched by coordinator.c's find_column_by_variants().

Usage:
    python3 scripts/to_flows.py path/to/input.csv
Writes: data/<input_basename>_offline.csv
"""
import sys, os, argparse
import pandas as pd
import re

REQUIRED = {
    'src_ip': ['source ip','src ip','src_ip','src','source_ip','source'],
    'src_port': ['source port','src port','src_port','sport','source_port'],
    'dst_ip': ['destination ip','dst ip','dst_ip','dst','destination_ip','dest'],
    'dst_port': ['destination port','dst port','dst_port','dport','destination_port'],
    'protocol': ['protocol','proto','Protocol'],
    'timestamp': ['timestamp','time','start_time','ts','epoch'],
    'duration': ['flow duration','duration','flow_duration','flow_length'],
    'packets': ['total fwd packets','total_fwd_packets','fwd_packets','packets','pkts','total_fwd_packets '],
    'label': ['label','class','attack','is_attack']
}

# Output header names expected by coordinator (case-insensitive match in C)
OUT_COLS = [
    'Source IP', 'Source Port', 'Destination IP', 'Destination Port',
    'Protocol', 'Timestamp', 'Flow Duration', 'Total Fwd Packets', 'Label'
]

def find_column(df_cols, variants):
    lower = {c.lower(): c for c in df_cols}
    for v in variants:
        v_low = v.lower()
        if v_low in lower:
            return lower[v_low]
    # try fuzzy: remove non-alnum
    for col in df_cols:
        col_s = re.sub(r'[^a-z0-9]','', col.lower())
        for v in variants:
            v_s = re.sub(r'[^a-z0-9]','', v.lower())
            if col_s == v_s:
                return col
    return None

def normalize(path):
    df = pd.read_csv(path, dtype=str, low_memory=False)
    cols = list(df.columns)
    mapping = {}
    missing = []
    for k, variants in REQUIRED.items():
        found = find_column(cols, variants)
        if found:
            mapping[k] = found
        else:
            missing.append(k)
    # If some required keys are missing, we'll still continue but fill missing fields with defaults (0/empty)
    out = pd.DataFrame()
    # timestamp
    if 'timestamp' in mapping:
        out['timestamp'] = pd.to_numeric(df[mapping['timestamp']], errors='coerce')
    else:
        out['timestamp'] = pd.Series([0]*len(df))
    # IPs and ports
    out['src_ip'] = df[mapping['src_ip']] if 'src_ip' in mapping else ''
    out['src_port'] = pd.to_numeric(df[mapping['src_port']], errors='coerce').fillna(0).astype(int) if 'src_port' in mapping else 0
    out['dst_ip'] = df[mapping['dst_ip']] if 'dst_ip' in mapping else ''
    out['dst_port'] = pd.to_numeric(df[mapping['dst_port']], errors='coerce').fillna(0).astype(int) if 'dst_port' in mapping else 0
    out['protocol'] = df[mapping['protocol']].fillna('').astype(str) if 'protocol' in mapping else ''
    out['duration'] = pd.to_numeric(df[mapping['duration']], errors='coerce').fillna(0).astype(float) if 'duration' in mapping else 0.0
    out['packets'] = pd.to_numeric(df[mapping['packets']], errors='coerce').fillna(0).astype(int) if 'packets' in mapping else 0
    out['label'] = df[mapping['label']].fillna('').astype(str) if 'label' in mapping else ''

    # Clean IP strings whitespace
    out['src_ip'] = out['src_ip'].astype(str).str.strip()
    out['dst_ip'] = out['dst_ip'].astype(str).str.strip()

    # Drop rows with missing crucial IPs
    before = len(out)
    out = out[(out['src_ip']!='') & (out['dst_ip']!='')]
    after = len(out)
    dropped = before - after

    base = os.path.basename(path)
    name = os.path.splitext(base)[0]
    out_path = os.path.join('data', f"{name}_offline.csv")
    # build final frame with LOWERCASE headers for fuzzy matching in coordinator.c
    # Order MUST be: timestamp, src_ip, src_port, dst_ip, dst_port, protocol, duration, packets, label
    final = pd.DataFrame()
    final['timestamp'] = out['timestamp']
    final['src_ip'] = out['src_ip']
    final['src_port'] = out['src_port'].astype(int)
    final['dst_ip'] = out['dst_ip']
    final['dst_port'] = out['dst_port'].astype(int)
    final['protocol'] = out['protocol']
    final['duration'] = out['duration']
    final['packets'] = out['packets'].astype(int)
    final['label'] = out['label']

    final.to_csv(out_path, index=False)
    print(f"[to_flows] wrote {out_path} ({after} rows). Dropped {dropped} rows missing IPs.")
    if missing:
        print(f"[to_flows] WARNING: The input had no columns for: {missing} (those fields filled with defaults where possible).")
    return out_path

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("csv", help="Input CSV file path")
    args = p.parse_args()
    os.makedirs('data', exist_ok=True)
    path = normalize(args.csv)
    print("Normalized to:", path)

