🚀 Project Overview

The PDC (Parallel Distributed Cyberattack Detection) system is an MPI-powered intrusion detection framework that processes normalized flow datasets to identify cyberattacks. It uses:

Entropy-based anomaly detection

CUSUM deviation detection

PCA reconstruction monitoring

Hybrid multi-detector fusion

It is optimized for multi-core and multi-node distributed environments, allowing fast processing of large network flow datasets.

📁 Repository Structure
mpiwork/
│── Makefile
│── pdc                         # Generated MPI executable
│
├── data/
│   ├── DrDoS_LDAP.csv
│   ├── Portmap.csv
│   ├── Portmap_offline_first100.csv
│   └── first100.py
│
├── output/
│   ├── attack_summary.txt
│   ├── cusum_alerts.txt
│   ├── entropy_alerts.txt
│   ├── pca_alerts.txt
│   ├── detection_log.txt
│   ├── detector_scores.csv
│   ├── detection_lead_time.csv
│   ├── evaluation_metrics.csv
│   ├── pcap_flows.txt
│   ├── combined_benign.txt
│   └── combined_malicious.txt
│
├── python/
│   ├── evaluate.py
│   └── plot_metrics.py
│
├── scripts/
│   ├── run.sh
│   ├── run_local.sh
│   ├── scalability_run.sh
│   ├── replay_pcap.sh
│   ├── capture_live.sh
│   ├── to_flows.py
│   └── collect_stats.sh
│
└── src/
    ├── main.c
    ├── coordinator.c
    ├── worker.c
    ├── detectors.c
    ├── detectors.h
    ├── block.c / block.h
    └── resource.c / resource.h

⭐ Features

🔥 Parallel detection using MPI across multiple processes/nodes

🧠 Multiple anomaly detectors: Entropy, CUSUM, PCA

📊 Detector score logs and full evaluation pipeline

📈 Graph generation for metrics and performance

🧹 Automatic CSV normalization with flexible column mapping

🧪 Scalability benchmarking tools

🏷️ Support for labeled datasets (BENIGN/Malicious)

🛠️ Technologies Used

C + MPI (OpenMPI)

Python (NumPy, pandas, matplotlib)

Bash scripting

Linux-based environment

📥 Installation
1. Install system dependencies
sudo apt install openmpi-bin libopenmpi-dev python3 python3-pip build-essential

2. Install Python packages
pip install pandas numpy matplotlib psutil GPUtil

⚙️ Building the MPI Program

From inside mpiwork/:

cd mpiwork
make


This builds:

./pdc

▶️ Running the System
Basic run
mpirun -np 4 ./pdc data/Portmap_offline_first100.csv

Automated full pipeline
./scripts/run.sh data/Portmap.csv 4

Local test (single process)
./scripts/run_local.sh data/Portmap.csv

🧽 CSV Normalization

The system expects standardized flow columns:

timestamp, src_ip, src_port, dst_ip, dst_port,
protocol, duration, packets, label


Normalize any dataset using:

python3 scripts/to_flows.py input.csv


Output:

data/<filename>_offline.csv

📤 Output Files

All results are stored in output/:

File	Description
detection_log.txt	Event-by-event detection log
entropy_alerts.txt	Entropy-based alerts
cusum_alerts.txt	CUSUM-based alerts
pca_alerts.txt	PCA reconstruction alerts
detector_scores.csv	Raw scores for every flow window
evaluation_metrics.csv	Precision, recall, F1, etc.
detection_lead_time.csv	Early detection latency
attack_summary.txt	Final summary of detected attacks
📊 Python Evaluation & Plotting
Compute evaluation metrics:
python3 python/evaluate.py data/Portmap_offline.csv

Plot metrics:
python3 python/plot_metrics.py output/evaluation_metrics.csv


This generates accuracy/F1/ROC-style visualizations.

🔧 Configuration & Detector Tuning

You may adjust detector sensitivity using environment variables:

Variable	Effect
ENTROPY_MIN_PKTS	Minimum packets before entropy check
ENTROPY_CONC_THRESHOLD	Entropy spike threshold
CUSUM_DIFF_THRESHOLD	CUSUM sensitivity
PCA_RECON_THRESHOLD	PCA reconstruction threshold

Example:

export CUSUM_DIFF_THRESHOLD=4.5
export ENTROPY_MIN_PKTS=20

mpirun -np 8 ./pdc data/Normalized.csv

⚡ Performance & Scalability

Included utilities:

scalability_run.sh – Runs the system using multiple process counts

collect_stats.sh – Records CPU/memory usage

gpu_profile.sh – Optional GPU profiling

MPI parallelism provides significant performance boosts with larger datasets.

🐞 Troubleshooting
Issue	Fix
mpicc: command not found	Install OpenMPI (sudo apt install libopenmpi-dev)
Missing CSV columns	Run through scripts/to_flows.py
Python errors	Ensure Python dependencies are installed
MPI hangs	Check file paths & number of processes
🤝 Contributing

Pull requests are welcome.
You can extend detectors, add ML-based models, or improve evaluation scripts.

📜 License

Add your preferred license:

MIT License

Apache License 2.0

GPLv3

If you'd like, I can also:
✅ Add shields/badges (build, license, contributors)
✅ Add architecture diagrams
✅ Auto-generate a CONTRIBUTING.md
✅ Produce a project logo

Just tell me!
