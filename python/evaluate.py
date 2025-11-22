#!/usr/bin/env python3
"""
evaluate_fixed.py
Fixed and cleaned version of evaluate.py
Reads:
  - data/<name>_offline.csv      (ground truth labels)
  - output/combined_malicious.txt (detected malicious IPs)
  - output/results.txt           (summary from coordinator)
Produces:
  - output/evaluation_report.txt
  - output/evaluation_metrics.csv
"""
import os
import sys
import time
import csv
import re
from typing import Dict, Any

try:
    import psutil  # type: ignore
except Exception:
    psutil = None
try:
    import GPUtil  # type: ignore
except Exception:
    GPUtil = None

# basic CLI parsing: first arg is data CSV; optional --debug flag prints sample rows
DEBUG = False
args = [a for a in sys.argv[1:]]
if '--debug' in args:
    DEBUG = True
    args.remove('--debug')

DATA_CSV = args[0] if len(args) > 0 else "data/flows_offline.csv"
# normalize possible Windows-style backslashes and relative path quirks
if DATA_CSV:
    DATA_CSV = os.path.normpath(DATA_CSV.replace('\\', '/'))
DETECTED_FILE = os.environ.get('DETECTED_FILE', "output/combined_malicious.txt")
RESULTS_FILE = os.environ.get('RESULTS_FILE', "output/results.txt")
OUT_REPORT = os.environ.get('OUT_REPORT', "output/evaluation_report.txt")
OUT_CSV = os.environ.get('OUT_CSV', "output/evaluation_metrics.csv")


def _normalize_header(name):
    return re.sub(r'[^a-z0-9]', '', name.lower()) if name else ''


def _find_column(fieldnames, variants):
    normalized = { _normalize_header(n): n for n in fieldnames if n }
    for variant in variants:
        key = _normalize_header(variant)
        if key in normalized:
            return normalized[key]
    return None


def _normalize_label(label):
    """Return canonical label. Attacks are returned as 'DrDoS_NTP', everything else 'BENIGN'."""
    if label is None:
        return "BENIGN"
    label_str = str(label).strip()
    low = label_str.lower()
    # if label contains common attack markers, treat as attack
    if any(tok in low for tok in ("drdos","Portmap", "ddos", "attack", "malicious")) or low in ("1", "true", "attack"):
        return "DrDoS_NTP"
    return "BENIGN"


# read ground-truth mapping: aggregate per source IP
def load_ground_truth(csv_path):
    """Return mapping src_ip -> canonical label ('DrDoS_NTP' or 'BENIGN')."""
    gt = {}
    if not os.path.exists(csv_path):
        return gt
    try:
        with open(csv_path, newline='', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames or []
            src_col = _find_column(fieldnames, [
                "Source IP", "src_ip", "src", "SourceIP", "Src IP", "SrcIP"
            ])
            label_col = _find_column(fieldnames, [
                "Label", "label", "class", "Class"
            ])
            if not src_col or not label_col:
                return gt
            for row in reader:
                src = (row.get(src_col) or "").strip()
                if not src:
                    continue
                label_norm = _normalize_label(row.get(label_col))
                # once an IP marked as attack, keep it as attack
                if gt.get(src) == "DrDoS_NTP":
                    continue
                if gt.get(src) == "Portmap":
                    continue
                gt[src] = label_norm
    except Exception:
        # swallow errors but return whatever parsed
        pass
    return gt


def load_detected(path):
    det = set()
    if not os.path.exists(path):
        return det
    with open(path, encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            det.add(parts[0].strip())
    return det


def evaluate(gt_map, detected_set):
    """Compute confusion matrix and derived metrics.
    We treat label == 'DrDoS_NTP' as the positive (attack) class.
    """
    has_ground_truth = len(gt_map) > 0
    total_attack = sum(1 for label in gt_map.values() if label == "DrDoS_NTP")
    total_benign = sum(1 for label in gt_map.values() if label != "DrDoS_NTP")

    if not has_ground_truth:
        # Unsupervised: no ground truth to compare. Provide counts and mark unsupervised.
        TP = 0
        FP = 0
        FN = 0
        TN = 0
        precision = 0.0
        recall = 0.0
        f1 = 0.0
        metrics = {
            "TP": TP, "FP": FP, "FN": FN, "TN": TN,
            "precision": precision, "recall": recall, "f1": f1, "fpr": None,
            "TPR": recall, "FPR": None,
            "total_attack_ips": total_attack, "total_benign_ips": total_benign,
            "is_unsupervised": True
        }
        return metrics

    TP = FP = TN = FN = 0
    for ip, label in gt_map.items():
        detected = ip in detected_set
        if label == "DrDoS_NTP":
            # attack (positive class)
            if detected:
                FP += 1
            else:
                FN += 1
        else:
            # benign (negative class)
            if detected:
                TP += 1
            else:
                TN += 1

    TPR = TP / (TP + FN) if (TP + FN) else 0.0
    FPR = FP / (FP + TN) if (FP + TN) else 0.0
    precision = TP / (TP + FP) if (TP + FP) else 0.0
    accuracy= (TP+TN)/(TP+TN+FP)
    recall = TPR
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    metrics = {
        "TP": TP, "FP": FP, "FN": FN, "TN": TN,
        "precision": precision, "recall": recall, "f1": f1, "fpr": FPR,
        "TPR": TPR, "FPR": FPR,
        "total_attack_ips": total_attack, "total_benign_ips": total_benign,
        "is_unsupervised": False
    }
    return metrics


def parse_results_summary(path):
    res = {}
    if not os.path.exists(path):
        return res
    with open(path, encoding='utf-8', errors='ignore') as f:
        for line in f:
            if '=' in line:
                k, v = line.strip().split('=', 1)
                res[k] = v
    return res


def parse_attack_summary(path):
    # same format as results summary
    return parse_results_summary(path)


def blocking_effectiveness(gt_map, detected_set, global_summary_path=None):
    total_attack_pkts = 0
    blocked_attack_pkts = 0

    ips_packets = {}
    if os.path.exists(DATA_CSV):
        with open(DATA_CSV, newline='', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for r in reader:
                src = (r.get('Source IP') or r.get('src') or r.get('SrcIP') or r.get('src_ip'))
                pk = r.get('Total Fwd Packets') or r.get('TotalFwdPackets') or r.get('fwd_pkts') or r.get('Total Fwd Packets ')
                try:
                    pkv = int(pk) if pk not in (None, "") else 0
                except Exception:
                    pkv = 0
                if src:
                    ips_packets[src] = ips_packets.get(src, 0) + pkv

    for ip, val in gt_map.items():
        if val == "DrDoS_NTP":
            total_attack_pkts += ips_packets.get(ip, 0)
            if ip in detected_set:
                blocked_attack_pkts += ips_packets.get(ip, 0)

    if total_attack_pkts == 0:
        total_attack_pkts = sum(1 for ip in gt_map if gt_map[ip] == "DrDoS_NTP")
        blocked_attack_pkts = sum(1 for ip in detected_set if gt_map.get(ip, "BENIGN") == "DrDoS_NTP")

    eff = (100.0 * blocked_attack_pkts / total_attack_pkts) if total_attack_pkts > 0 else None
    return {"total_attack_pkts": total_attack_pkts, "blocked_attack_pkts": blocked_attack_pkts, "blocking_percentage": eff}


def blocking_metrics(gt_map, detected_set, global_summary_path=None):
    total_attack_pkts = 0
    blocked_attack_pkts = 0
    total_benign_pkts = 0
    collateral_blocked_pkts = 0

    ips_packets = {}
    if os.path.exists(DATA_CSV):
        with open(DATA_CSV, newline='', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for r in reader:
                src = (r.get('Source IP') or r.get('src') or r.get('SrcIP') or r.get('src_ip'))
                pk = r.get('Total Fwd Packets') or r.get('TotalFwdPackets') or r.get('fwd_pkts') or r.get('Total Fwd Packets ')
                try:
                    pkv = int(pk) if pk not in (None, "") else 0
                except Exception:
                    pkv = 0
                if src:
                    ips_packets[src] = ips_packets.get(src, 0) + pkv

    for ip, val in gt_map.items():
        pkt = ips_packets.get(ip, 0)
        if val == "DrDoS_NTP":
            total_attack_pkts += pkt
            if ip in detected_set:
                blocked_attack_pkts += pkt
        else:
            total_benign_pkts += pkt
            if ip in detected_set:
                collateral_blocked_pkts += pkt

    if total_attack_pkts == 0:
        total_attack_pkts = sum(1 for ip in gt_map if gt_map[ip] == "DrDoS_NTP")
        blocked_attack_pkts = sum(1 for ip in detected_set if gt_map.get(ip, "BENIGN") == "DrDoS_NTP")
    if total_benign_pkts == 0:
        total_benign_pkts = sum(1 for ip in gt_map if gt_map[ip] != "DrDoS_NTP")
        collateral_blocked_pkts = sum(1 for ip in detected_set if gt_map.get(ip, "BENIGN") != "DrDoS_NTP")

    attack_dropped_pct = (100.0 * blocked_attack_pkts / total_attack_pkts) if total_attack_pkts > 0 else None
    collateral_pct = (100.0 * collateral_blocked_pkts / total_benign_pkts) if total_benign_pkts > 0 else None

    return {
        'total_attack_pkts': total_attack_pkts,
        'blocked_attack_pkts': blocked_attack_pkts,
        'attack_dropped_pct': attack_dropped_pct,
        'total_benign_pkts': total_benign_pkts,
        'collateral_blocked_pkts': collateral_blocked_pkts,
        'collateral_pct': collateral_pct
    }


def compute_detection_lead_time(data_csv, results_file):
    """
    Computes Detection Lead Time, Window Delay, and Processing Delay.
    Assumes data_csv contains ground_truth and results_file contains combined_prediction per window.
    Returns a dict with the metrics in seconds.
    """
    gt_windows = []
    pred_windows = []
    window_time = None
    processing_delay = None
    # Read ground truth windows. If the configured data_csv doesn't exist or
    # doesn't contain an explicit ground_truth column, search other CSVs in
    # likely data directories for the first attack row (label != BENIGN).
    candidate_files = [data_csv]
    # primary data dir derived from DATA_CSV
    data_dir = os.path.dirname(data_csv) or 'data'
    searched_dirs = [data_dir]
    # also consider data directory next to this script (mpiwork/data)
    script_data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data'))
    if script_data_dir not in searched_dirs:
        searched_dirs.append(script_data_dir)
    # Try each directory and collect CSVs
    for d in searched_dirs:
        try:
            for fn in os.listdir(d):
                path = os.path.join(d, fn)
                if path not in candidate_files and fn.lower().endswith('.csv'):
                    candidate_files.append(path)
        except Exception:
            continue

    for path in candidate_files:
        if not os.path.exists(path):
            continue
        try:
            with open(path, newline='', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
                fieldnames = reader.fieldnames or []
                gt_col = _find_column(fieldnames, ["ground_truth", "is_attack", "attack", "gt"])
                label_col = _find_column(fieldnames, ["label", "Label", "class"])
                time_col = _find_column(fieldnames, ["timestamp", "window_time", "time"])
                for i, row in enumerate(reader):
                    # Prefer explicit ground truth column if available
                    if gt_col and row.get(gt_col) is not None and str(row.get(gt_col)).strip() != "":
                        try:
                            gt = int(float(row.get(gt_col)))
                        except Exception:
                            gt = 1 if str(row.get(gt_col)).strip().lower() in ('1','true','attack','drdos') else 0
                    else:
                        # Fall back to label column heuristics
                        val = (row.get(label_col) or "").strip()
                        gt = 1 if val and val.upper() not in ("BENIGN","0","FALSE") else 0
                    if gt == 1:
                        gt_windows.append(i)
                        if time_col and row.get(time_col):
                            try:
                                window_time = float(row.get(time_col))
                            except Exception:
                                window_time = None
                        break
            # stop searching once we found at least one ground-truth window
            if gt_windows:
                break
        except Exception:
            continue
    # Read prediction windows from results_file. If not present, try the
    # results/ output directory next to this script.
    resolved_results = results_file
    if not os.path.exists(resolved_results):
        alt = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'output', os.path.basename(results_file)))
        if os.path.exists(alt):
            resolved_results = alt

    if os.path.exists(resolved_results):
        with open(resolved_results, encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if 'combined_prediction=1' in line or 'combined_prediction = 1' in line or 'combined_malicious_count' in line:
                    pred_windows.append(i)
                    # Try to extract processing time if present
                    if 'processing_time=' in line:
                        try:
                            processing_delay = float(line.split('processing_time=')[1].split()[0])
                        except Exception:
                            pass
                    break
    if gt_windows and pred_windows:
        window_delay = abs(pred_windows[0] - gt_windows[0])
    else:
        window_delay = None
    # Fallback for processing delay
    if processing_delay is None:
        processing_delay = 0.0
    # Lead time is sum of window delay and processing delay
    if window_delay is not None:
        detection_lead_time = window_delay + processing_delay
    else:
        detection_lead_time = None
    return {
        "Detection Lead Time": detection_lead_time,
        "Window Delay": window_delay,
        "Processing Delay": processing_delay
    }
def load_runtime_resources(path="output/resource_stats.txt"):
    stats: Dict[str, Any] = {}
    if not os.path.exists(path):
        return stats
    with open(path, encoding='utf-8', errors='ignore') as f:
        for line in f:
            if '=' not in line:
                continue
            k, v = line.strip().split('=', 1)
            stats[k] = v
    for key, value in list(stats.items()):
        if key in ("input_file",) or isinstance(value, (int, float)):
            continue
        if isinstance(value, str):
            if value.upper() == "N/A":
                continue
            try:
                num = float(value)
                stats[key] = num
            except ValueError:
                try:
                    stats[key] = int(value)
                except ValueError:
                    pass
    return stats



def compute_scalability_metrics(scal_csv_path: str = None):
    """
    Parse a scalability CSV and compute time and efficiency for 2,4,8 workers.
    Expected CSV columns: nodes, run_time_s (or run), pps, gbps (optional).
    Efficiency is computed relative to the 2-worker baseline (if present) as:
      efficiency(N) = (T_baseline * N_baseline) / (T_N * N) * 100
    Returns a dict with keys like '2_workers_time_s' and '2_workers_eff_pct'.
    """
    # default path: ../output/metrics/scalability.csv relative to this script
    if scal_csv_path is None:
        scal_csv_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'output', 'metrics', 'scalability.csv'))
    metrics = {}
    if not os.path.exists(scal_csv_path):
        return metrics

    rows = []
    try:
        with open(scal_csv_path, newline='', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for r in reader:
                rows.append(r)
    except Exception:
        return metrics

    times = {}
    for r in rows:
        # try common column names
        try:
            nodes = int((r.get('nodes') or r.get('workers') or r.get('np') or '').strip())
        except Exception:
            continue
        try:
            run = r.get('run_time_s') or r.get('run') or r.get('time') or r.get('runtime')
            run_v = float(run) if run not in (None, '') else None
        except Exception:
            run_v = None
        times[nodes] = run_v

    # pick baseline: prefer 2 workers if available, else smallest available
    baseline_N = None
    if 2 in times and times.get(2) is not None:
        baseline_N = 2
    else:
        ks = sorted([k for k in times.keys() if times.get(k) is not None])
        if ks:
            baseline_N = ks[0]

    baseline_time = times.get(baseline_N) if baseline_N else None

    for N in (2, 4, 8):
        t = times.get(N)
        metrics[f"{N}_workers_time_s"] = t if t is not None else None
        if t is not None and baseline_time is not None and baseline_time > 0:
            eff = (baseline_time * (baseline_N or 1)) / (t * N) * 100.0
            try:
                metrics[f"{N}_workers_eff_pct"] = round(float(eff), 2)
            except Exception:
                metrics[f"{N}_workers_eff_pct"] = None
        else:
            metrics[f"{N}_workers_eff_pct"] = None

    return metrics

# Scalability analysis: computed from output/metrics/scalability.csv when present.

def print_progress_bar(current, total, width=40):
    frac = current / total if total > 0 else 1.0
    filled = int(width * frac)
    bar = "[" + "#" * filled + "-" * (width - filled) + "]"
    pct = frac * 100
    print(f"{bar} {pct:.1f}% ({current}/{total})", end='\r')


def main():
    start_time = time.time()
    print("\033[1;36m[*]\033[0m Loading ground truth...")
    gt = load_ground_truth(DATA_CSV)

    print(f"\033[1;36m[*]\033[0m Loading detected malicious list...")
    det = load_detected(DETECTED_FILE)

    print(f"\033[1;36m[*]\033[0m Evaluating metrics...")
    metrics = evaluate(gt, det)
    be = blocking_effectiveness(gt, det, DATA_CSV)
    be_ext = blocking_metrics(gt, det, DATA_CSV)
    ressum = parse_results_summary(RESULTS_FILE)
    attack_sum = parse_attack_summary('output/attack_summary.txt')
    # Detection Lead Time calculation
    detection_lead_metrics = compute_detection_lead_time(DATA_CSV, RESULTS_FILE)
    # Scalability analysis: try to compute from metrics CSV (output/metrics/scalability.csv)
    scalability_metrics = compute_scalability_metrics()

    # Calculate system performance metrics
    detection_time = time.time() - start_time
    total_flows = int(ressum.get('processed_flows', 0))
    total_packets = int(attack_sum.get('total_packets', 0)) if attack_sum else 0

    # Throughput: flows per second
    throughput_fps = total_flows / detection_time if detection_time > 0 else 0

    # Processing rate: windows per second (100-flow windows)
    windows_processed = total_flows / 100 if total_flows > 0 else 0
    processing_rate = windows_processed / detection_time if detection_time > 0 else 0

    # Estimate traffic rate in Mbps (assuming avg 60 bytes per packet + headers)
    avg_bytes_per_packet = 60
    total_bytes = total_packets * avg_bytes_per_packet
    traffic_rate_mbps = (total_bytes * 8) / (detection_time * 1_000_000) if detection_time > 0 else 0

    runtime_stats = load_runtime_resources()
    cpu_percent = runtime_stats.get('cpu_percent', 'N/A')
    mem_used = runtime_stats.get('mem_used_mb', 'N/A')
    mem_total = runtime_stats.get('mem_total_mb', 'N/A')
    mem_percent = runtime_stats.get('mem_percent', 'N/A')
    net_rate_mbps = runtime_stats.get('net_rate_mbps', 'N/A')
    gpu_percent = runtime_stats.get('gpu_percent', 'N/A')
    if cpu_percent == 'N/A' and psutil:
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
        except Exception:
            pass
    if mem_used == 'N/A' and psutil:
        try:
            vm = psutil.virtual_memory()
            mem_used = vm.used / (1024 * 1024)
            mem_total = vm.total / (1024 * 1024)
            mem_percent = vm.percent
        except Exception:
            pass
    if net_rate_mbps == 'N/A' and psutil:
        try:
            net = psutil.net_io_counters()
            net_bytes = (net.bytes_sent + net.bytes_recv)
            net_rate_mbps = (net_bytes * 8) / (detection_time * 1_000_000) if detection_time > 0 else 0
        except Exception:
            pass
    if gpu_percent == 'N/A' and GPUtil:
        try:
            gpus = GPUtil.getGPUs()
            if gpus:
                gpu_percent = round(gpus[0].load * 100.0, 1)
        except Exception:
            pass

    # Display results with beautiful formatting
    print("\n\033[1;32m╔════════════════════════════════════╗\033[0m")
    print("\033[1;32m║  📋 Evaluation Report 📋        ║\033[0m")
    print("\033[1;32m╚════════════════════════════════════╝\033[0m\n")

    # Check if ground truth is available
    has_ground_truth = len(gt) > 0
    is_unsupervised = metrics.get('is_unsupervised', False)

    if has_ground_truth:

        print("\033[1;32m┌─ 📊 Supervised Metrics ─┐\033[0m")
        tp = metrics.get('TP', 0)
        fp = metrics.get('FP', 0)
        fn = metrics.get('FN', 0)
        precision = metrics.get('precision', 0)
        recall = metrics.get('recall', 0)
        f1 = metrics.get('f1', 0)

        tp_color = "\033[1;32m" if tp > 0 else "\033[1;37m"
        fp_color = "\033[1;31m" if fp > 0 else "\033[1;32m"
        fn_color = "\033[1;31m" if fn > 0 else "\033[1;32m"

        print(f"  {tp_color}✓ True Positives (TP):\033[0m {tp}")
        print(f"  {fp_color}✗ False Positives (FP):\033[0m {fp}")
        print(f"  {fn_color}⚠ False Negatives (FN):\033[0m {fn}")
        print(f"  \033[1;36m📈 Precision:\033[0m {precision:.3f}")
        print(f"  \033[1;36m📈 Recall:\033[0m {recall:.3f}")
        print(f"  \033[1;36m📈 F1-Score:\033[0m {f1:.3f}")
        print("\033[1;32m└────────────────────────────────┘\033[0m\n")

        # Accuracy Metrics table
        fpr = metrics.get('fpr', None)
        fpr_display = f"{fpr:.3f}" if (fpr is not None) else "N/A"
        print("\033[1;32m┌─ 📈 Accuracy Metrics ─┐\033[0m")
        print(f"  ✓ Precision: \033[1;36m{precision:.3f}\033[0m")
        print(f"  ✓ Recall:    \033[1;36m{recall:.3f}\033[0m")
        print(f"  ✓ F1 Score:  \033[1;36m{f1:.3f}\033[0m")
        print(f"  ✓ FPR:       \033[1;36m{fpr_display}\033[0m")
        print("\033[1;32m└────────────────────────────────┘\033[0m\n\n")


        # Display processing summary
        print("\033[1;32m┌─ ⚙️ Processing Summary ─┐\033[0m")
        processed_flows = ressum.get('processed_flows', '0')
        detected_entropy = ressum.get('detected_entropy', '0')
        detected_cusum = ressum.get('detected_cusum', '0')
        detected_pca = ressum.get('detected_pca', '0')
        combined_malicious = ressum.get('combined_malicious_count', '0')
        print(f"  ✓ Processed flows: \033[1;36m{processed_flows}\033[0m")
        print(f"  ✓ Detected (Entropy): \033[1;36m{detected_entropy}\033[0m")
        print(f"  ✓ Detected (CUSUM): \033[1;36m{detected_cusum}\033[0m")
        print(f"  ✓ Detected (PCA): \033[1;36m{detected_pca}\033[0m")
        print(f"  ✓ Combined malicious: \033[1;31m{combined_malicious}\033[0m")
        print("\033[1;32m└────────────────────────────────┘\033[0m\n")

        print("\033[1;32m┌─ 🚨 Attack Summary ─┐\033[0m")
        mal_ips = attack_sum.get('malicious_ip_count', '0')
        tot_ips = attack_sum.get('total_ips', '0')
        mal_pkt_pct = float(attack_sum.get('malicious_packets_pct', '0')) if attack_sum else 0.0
        ddos_det = attack_sum.get('ddos_detected', '0') if attack_sum else '0'

        print(f"  \033[1;31m✓ Malicious IPs detected:\033[0m {mal_ips} / {tot_ips}")
        print(f"  \033[1;31m✓ Malicious packets:\033[0m {attack_sum.get('malicious_packets', '0')} / {attack_sum.get('total_packets', '0')}")
        pkt_pct_color = "\033[1;31m" if mal_pkt_pct >= 1.0 else "\033[1;33m"
        print(f"  \033[1;31m✓ Malicious traffic:\033[0m {pkt_pct_color}{mal_pkt_pct:.2f}%\033[0m")
        ddos_status = "\033[1;31m🚨 ATTACK DETECTED\033[0m" if ddos_det == "1" else "\033[1;32m✓ No DDoS\033[0m"
        print(f"  \033[1;31m✓ DDoS Status:\033[0m {ddos_status}")
        print("\033[1;32m└────────────────────────────────┘\033[0m\n")

        # Blocking Effectiveness table (attack drop + collateral)
        print("\033[1;32m┌─ 🛡️ Blocking Effectiveness ─┐\033[0m")
        ad = be_ext.get('attack_dropped_pct')
        ad_disp = f"{ad:.2f}%" if ad is not None else 'N/A'
        coll = be_ext.get('collateral_pct')
        coll_disp = f"{coll:.2f}%" if coll is not None else 'N/A'
        print(f"  ✓ Attack traffic dropped: \033[1;36m{ad_disp}\033[0m")
        print(f"  ✓ Collateral impact:      \033[1;36m{coll_disp}\033[0m")
        print("\033[1;32m└────────────────────────────────┘\033[0m\n")

        # Display system performance metrics
        print("\033[1;32m┌─ ⚡ System Performance ─┐\033[0m")
        print(f"  ✓ Total network flows: \033[1;36m{total_flows:,}\033[0m")
        print(f"  ✓ Detection time: \033[1;36m{detection_time:.2f}s\033[0m")
        print(f"  ✓ Processing throughput: \033[1;36m{throughput_fps:,.0f}\033[0m flows/sec")
        print(f"  ✓ Processing rate: \033[1;36m{processing_rate:,.0f}\033[0m windows/sec")
        print(f"  ✓ Estimated traffic rate: \033[1;36m{traffic_rate_mbps:.2f}\033[0m Mbps")
        # Detection Lead Time metrics
        print(f"  ✓ Detection Lead Time: \033[1;36m{detection_lead_metrics['Detection Lead Time']}\033[0m sec")
        print(f"  ✓ Window Delay: \033[1;36m{detection_lead_metrics['Window Delay']}\033[0m sec")
        print(f"  ✓ Processing Delay: \033[1;36m{detection_lead_metrics['Processing Delay']}\033[0m sec")
        # Scalability analysis (if available)
        if scalability_metrics:
            print("\n  ✓ Scalability:\n")
            print("    Configuration     Time (s)     Efficiency (%)")
            for N in (2, 4, 8):
                t = scalability_metrics.get(f"{N}_workers_time_s")
                e = scalability_metrics.get(f"{N}_workers_eff_pct")
                t_disp = f"{t:.3f}" if isinstance(t, (int, float)) else "N/A"
                e_disp = f"{e:.2f}%" if isinstance(e, (int, float)) else "N/A"
                print(f"    {N:>2} Workers        {t_disp:>8}       {e_disp:>8}")
        print("\033[1;32m└────────────────────────────────┘\033[0m\n")

        # Resource Utilization
        print("\033[1;32m┌─ 🖥️ Resource Utilization ─┐\033[0m")
        cpu_disp = f"{cpu_percent:.1f}%" if isinstance(cpu_percent, (int, float)) else cpu_percent
        print(f"  ✓ CPU Usage: \033[1;36m{cpu_disp}\033[0m")
        gpu_disp = f"{gpu_percent}%" if isinstance(gpu_percent, (int, float)) else gpu_percent
        print(f"  ✓ GPU Usage: \033[1;36m{gpu_disp}\033[0m")
        if isinstance(mem_used, (int, float)):
            mu = mem_used
            mt = mem_total if isinstance(mem_total, (int, float)) else None
            mp = f"{mem_percent}%" if isinstance(mem_percent, (int, float)) else mem_percent
            mt_display = f"{mt:.1f}MB" if isinstance(mt, (int, float)) else 'N/A'
            print(f"  ✓ Memory: \033[1;36m{mu:.1f}MB / {mt_display}\033[0m ({mp})")
        else:
            print(f"  ✓ Memory: \033[1;36m{mem_used}\033[0m")
        net_disp = f"{net_rate_mbps:.2f} Mbps" if isinstance(net_rate_mbps, (int, float)) else net_rate_mbps
        print(f"  ✓ Network I/O rate: \033[1;36m{net_disp}\033[0m")
        print("\033[1;32m└────────────────────────────────┘\033[0m\n")

    # ensure output directory exists
    outdir = os.path.dirname(OUT_REPORT)
    if outdir and not os.path.exists(outdir):
        try:
            os.makedirs(outdir, exist_ok=True)
        except Exception as e:
            print("Could not create output directory:", outdir, e)

    # write report
    with open(OUT_REPORT, "w", encoding='utf-8') as f:
        f.write("═" * 50 + "\n")
        f.write("  PDC - Evaluation Report\n")
        f.write("═" * 50 + "\n\n")

        if has_ground_truth:
            f.write("SUPERVISED EVALUATION (Ground Truth Available)\n")
            f.write("-" * 50 + "\n\n")
            f.write(f"Ground-truth IPs:\n")
            f.write(f"  • Attack IPs: {sum(1 for v in gt.values() if v!='DrDoS_NTP')}\n")
            f.write(f"  • Benign IPs: {sum(1 for v in gt.values() if v=='DrDoS_NTP')}\n\n")
            f.write(f"Detected IPs: {len(det)}\n\n")
            f.write("Supervised Metrics:\n")
            for k in ["TP", "FP", "FN", "TN"]:
                f.write(f"  • {k}: {metrics.get(k)}\n")
            f.write(f"  • Precision: {metrics.get('precision', 0):.3f}\n")
            f.write(f"  • Recall: {metrics.get('recall', 0):.3f}\n")
            f.write(f"  • F1-Score: {metrics.get('f1', 0):.3f}\n")
            f.write(f"  • FPR: {metrics.get('fpr', 'N/A')}\n")
            f.write("\nAccuracy Metrics:\n")
            f.write("-" * 30 + "\n")
            f.write(f"  • Precision: {metrics.get('precision', 0):.3f}\n")
            f.write(f"  • Recall:    {metrics.get('recall', 0):.3f}\n")
            f.write(f"  • F1 Score:  {metrics.get('f1', 0):.3f}\n")
            f.write(f"  • FPR:       {metrics.get('fpr', 'N/A')}\n")
        else:
            f.write("UNSUPERVISED EVALUATION (Ensemble Detection)\n")
            f.write("-" * 50 + "\n\n")
            f.write(f"Total IPs analyzed: {len(gt) if len(gt) > 0 else 'N/A'}\n")
            f.write(f"IPs flagged as malicious: {len(det)}\n\n")
            f.write("Ensemble Detection Metrics:\n")
            f.write(f"  • TP (True Positives): {metrics.get('TP', 0)} (ensemble voted)\n")
            f.write(f"  • FP (False Positives): {metrics.get('FP', 0)} (all detections trusted)\n")
            f.write(f"  • Confidence: {metrics.get('precision', 0):.1%}\n\n")
            f.write("\nAccuracy Metrics:\n")
            f.write("-" * 30 + "\n")
            f.write(f"  • Precision: {metrics.get('precision', 0):.3f}\n")
            f.write(f"  • Recall:    {metrics.get('recall', 0):.3f}\n")
            f.write(f"  • F1 Score:  {metrics.get('f1', 0):.3f}\n")
            f.write(f"  • FPR:       {metrics.get('fpr', 'N/A')}\n\n")
            f.write("📌 NOTE: In unsupervised mode, all detections are trusted as True Positives\n")
            f.write("because multiple algorithms voted to flag them (ensemble voting).\n")
            f.write("Detection confidence based on: Entropy, CUSUM, and PCA detectors.\n\n")

        f.write("\nBlocking Effectiveness:\n")
        f.write("-" * 30 + "\n")
        if be['total_attack_pkts'] > 0:
            f.write(f"  • Total attack packets: {be['total_attack_pkts']}\n")
            f.write(f"  • Blocked attack packets: {be['blocked_attack_pkts']}\n")
            f.write(f"  • Blocking percentage: {be['blocking_percentage']:.2f}%\n")
            # Extended blocking metrics
            f.write(f"  • Attack traffic dropped (pct): {be_ext.get('attack_dropped_pct', 'N/A')}\n")
            f.write(f"  • Collateral impact (pct): {be_ext.get('collateral_pct', 'N/A')}\n")
        else:
            f.write(f"  • Unsupervised mode: Blocking effectiveness based on detected IPs only\n")

        f.write("\nProcessing Summary:\n")
        f.write("-" * 30 + "\n")
        for k, v in ressum.items():
            f.write(f"  • {k} = {v}\n")

        # Resource utilization report
        f.write('\nResource Utilization:\n')
        f.write('-' * 30 + '\n')
        cpu_val = f"{cpu_percent:.1f}%" if isinstance(cpu_percent, (int, float)) else cpu_percent
        gpu_val = f"{gpu_percent}%" if isinstance(gpu_percent, (int, float)) else gpu_percent
        f.write(f"  • CPU Usage: {cpu_val}\n")
        f.write(f"  • GPU Usage: {gpu_val}\n")
        if isinstance(mem_used, (int, float)) and isinstance(mem_total, (int, float)):
            f.write(f"  • Memory: {mem_used:.1f}MB / {mem_total:.1f}MB ({mem_percent}%)\n")
        else:
            f.write(f"  • Memory: {mem_used}\n")
        f.write(f"  • Network I/O rate (Mbps): {net_rate_mbps}\n")

        # Unsupervised summary if available
        attack_sum = parse_attack_summary('output/attack_summary.txt')
        if attack_sum and not has_ground_truth:
            f.write('\nUnsupervised Attack Analysis:\n')
            f.write("-" * 30 + "\n")
            for k in ['malicious_ip_count', 'total_ips', 'malicious_ip_pct', 'malicious_packets', 'total_packets', 'malicious_packets_pct', 'ddos_threshold_pct', 'ddos_detected']:
                if k in attack_sum:
                    if 'pct' in k:
                        f.write(f"  • {k} = {attack_sum[k]}%\n")
                    elif k == 'ddos_detected':
                        status = "🚨 ATTACK DETECTED" if attack_sum[k] == "1" else "✓ No DDoS"
                        f.write(f"  • {k} = {status}\n")
                    else:
                        f.write(f"  • {k} = {attack_sum[k]}\n")

            # Scalability analysis removed; no additional report lines are written.

    # write CSV metrics
    outdir_csv = os.path.dirname(OUT_CSV)
    if outdir_csv and not os.path.exists(outdir_csv):
        try:
            os.makedirs(outdir_csv, exist_ok=True)
        except Exception:
            pass

    with open(OUT_CSV, "w", newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "value"])
        for k, v in metrics.items():
            writer.writerow([k, v])
        for k, v in be.items():
            writer.writerow([k, v])
        for k, v in ressum.items():
            writer.writerow([k, v])
        # Resource utilization metrics
        writer.writerow(['cpu_percent', cpu_percent])
        writer.writerow(['gpu_percent', gpu_percent])
        writer.writerow(['mem_used_mb', mem_used])
        writer.writerow(['mem_total_mb', mem_total])
        writer.writerow(['mem_percent', mem_percent])
        writer.writerow(['net_rate_mbps', net_rate_mbps])
        # Extended blocking metrics
        writer.writerow(['attack_dropped_pct', be_ext.get('attack_dropped_pct')])
        writer.writerow(['collateral_pct', be_ext.get('collateral_pct')])
        # Detection Lead Time metrics
        for k, v in detection_lead_metrics.items():
            writer.writerow([k, v])
        # Scalability metrics (if available)
        for k, v in scalability_metrics.items():
            writer.writerow([k, v])

    # Also write detection lead time into a dedicated CSV in the output folder
    out_lead = os.path.dirname(OUT_REPORT)
    lead_csv = os.path.join(out_lead, 'detection_lead_time.csv') if out_lead else 'output/detection_lead_time.csv'
    try:
        with open(lead_csv, 'w', newline='', encoding='utf-8') as lf:
            lw = csv.writer(lf)
            lw.writerow(['metric', 'value'])
            for k, v in detection_lead_metrics.items():
                lw.writerow([k, v])
    except Exception:
        pass

    print("\n\033[1;32m✓\033[0m Evaluation complete!")
    print(f"\033[1;36m  📄 Report:\033[0m {OUT_REPORT}")
    print(f"\033[1;36m  📊 Metrics CSV:\033[0m {OUT_CSV}")


if __name__ == "__main__":
    main()

