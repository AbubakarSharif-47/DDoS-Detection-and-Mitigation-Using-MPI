# 🚀 PDC (Parallel Distributed Cyberattack Detection)

The **PDC** system is an MPI-powered intrusion detection framework that processes normalized flow datasets to identify cyberattacks. It uses:

- **Entropy-based anomaly detection**
- **CUSUM deviation detection**
- **PCA reconstruction monitoring**
- **Hybrid multi-detector fusion**

It is optimized for **multi-core and multi-node distributed environments**, allowing fast processing of large network flow datasets.

---


# ⭐ Features
## 🔥 Parallel detection using MPI across multiple processes/nodes

🧠 Multiple anomaly detectors: Entropy, CUSUM, PCA

📊 Detector score logs and full evaluation pipeline

📈 Graph generation for metrics and performance

🧹 Automatic CSV normalization with flexible column mapping

🧪 Scalability benchmarking tools

🏷️ Support for labeled datasets (BENIGN/Malicious)

# Technologies Used
 C + MPI (OpenMPI)

Python (NumPy, pandas, matplotlib)

Bash scripting

Linux-based environment

# 📥 Installation
1. Install system dependencies
Bash

sudo apt install openmpi-bin libopenmpi-dev python3 python3-pip build-essential
2. Install Python packages
Bash

pip install pandas numpy matplotlib psutil GPUtil
# ⚙️ Building the MPI Program
Bash
cd main directory
make
This builds the executable: ./pdc

# ▶️ Running the System
Basic run
Bash

mpirun -np 4 ./pdc data/DdosCSV.csv
Automated full pipeline
Bash

./scripts/run.sh data/Portmap.csv 4
Local test (single process)
Bash


# 📤 Output Files
All results are stored in the output/ folder:

File	Description
detection_log.txt	Event-by-event detection log
entropy_alerts.txt	Entropy-based alerts
cusum_alerts.txt	CUSUM-based alerts
pca_alerts.txt	PCA reconstruction alerts
detector_scores.csv	Raw scores for each flow window
evaluation_metrics.csv	Precision, recall, F1, etc.
detection_lead_time.csv	Early detection latency
attack_summary.txt	Final summary of detected attacks

Export to Sheets

# 📊 Python Evaluation & Plotting
Compute evaluation metrics:

Bash

python3 python/evaluate.py data/DdosCSV.csv
Generate plots:

Bash

python3 python/plot_metrics.py output/evaluation_metrics.csv
This generates accuracy, F1-score, ROC-style visualizations, etc.

# 🔧 Configuration & Detector Tuning
Adjust detector sensitivity using environment variables:

Variable	Effect
ENTROPY_MIN_PKTS	Minimum packets before entropy check
ENTROPY_CONC_THRESHOLD	Entropy spike threshold
CUSUM_DIFF_THRESHOLD	CUSUM sensitivity
PCA_RECON_THRESHOLD	PCA reconstruction threshold

Export to Sheets

Example:

Bash

export CUSUM_DIFF_THRESHOLD=4.5
export ENTROPY_MIN_PKTS=20

mpirun -np 8 ./pdc data/Normalized.csv
# ⚡ Performance & Scalability
Included utilities:

scalability_run.sh: Test MPI scaling across multiple process counts

collect_stats.sh: Collect CPU/memory usage

gpu_profile.sh: Optional GPU profiling

MPI significantly improves performance on large datasets.

# 🐞 Troubleshooting
Issue	Fix
mpicc: command not found	Install OpenMPI: sudo apt install libopenmpi-dev
Missing CSV columns	Run normalization: scripts/to_flows.py
Python import errors	Check required packages
MPI hangs	Check file paths, dataset, or number of processes

Export to Sheets

# 🤝 Contributers
Abubakar Sharif, Husssain Khaqan, Umar Zeb
