# 🚀 Project Overview

The **PDC (Parallel Distributed Cyberattack Detection)** system is an MPI-powered intrusion detection framework that processes normalized flow datasets to identify cyberattacks. It uses:

- **Entropy-based anomaly detection**
- **CUSUM deviation detection**
- **PCA reconstruction monitoring**
- **Hybrid multi-detector fusion**

It is optimized for **multi-core and multi-node distributed environments**, allowing fast processing of large network flow datasets.

---

# 📁 Repository Structure

mpiwork/
│── Makefile
│── pdc # Generated MPI executable
│
├── data/
│ ├── DrDoS_LDAP.csv
│ ├── Portmap.csv
│ ├── Portmap_offline_first100.csv
│ └── first100.py
│
├── output/
│ ├── attack_summary.txt
│ ├── cusum_alerts.txt
│ ├── entropy_alerts.txt
│ ├── pca_alerts.txt
│ ├── detection_log.txt
│ ├── detector_scores.csv
│ ├── detection_lead_time.csv
│ ├── evaluation_metrics.csv
│ ├── pcap_flows.txt
│ ├── combined_benign.txt
│ └── combined_malicious.txt
│
├── python/
│ ├── evaluate.py
│ └── plot_metrics.py
│
├── scripts/
│ ├── run.sh
│ ├── run_local.sh
│ ├── scalability_run.sh
│ ├── replay_pcap.sh
│ ├── capture_live.sh
│ ├── to_flows.py
│ └── collect_stats.sh
│
└── src/
├── main.c
├── coordinator.c
├── worker.c
├── detectors.c
├── detectors.h
├── block.c / block.h
└── resource.c / resource.h
