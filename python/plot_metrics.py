#!/usr/bin/env python3
"""
plot_metrics.py
Read `output/evaluation_metrics.csv`, print a CLI-friendly summary with ASCII bars,
and save a PNG visualization (bar chart + confusion-matrix heatmap) if matplotlib is available.

Usage:
  python python/plot_metrics.py output/evaluation_metrics.csv
"""
import csv
import sys
import os

def read_metrics(path):
    m = {}
    with open(path, newline='') as f:
        r = csv.reader(f)
        for row in r:
            if not row or row[0].startswith('#'): continue
            if len(row) < 2: continue
            key = row[0].strip()
            val = row[1].strip()
            try:
                if '.' in val:
                    v = float(val)
                else:
                    v = int(val)
            except:
                v = val
            m[key] = v
    return m

def ascii_bar(label, value, width=40, maxv=None):
    try:
        v = float(value)
    except:
        v = 0.0
    if maxv is None:
        maxv = v if v>0 else 1.0
    filled = int(round((v / maxv) * width)) if maxv>0 else 0
    # Use solid block for filled portion and light shade for remainder
    filled_ch = '█'
    empty_ch = '░'
    bar = filled_ch * filled + empty_ch * (width - filled)
    return f"{label:>3} |{bar}| {int(v) if float(v).is_integer() else round(v,2)}"

def print_summary(m):
    print_report()

def print_report(report_path='output/evaluation_report.txt'):
    """Print and store evaluation report from file with enhanced formatting."""
    if os.path.exists(report_path):
        print("\n" + "━"*70)
        print("📊 EVALUATION REPORT 📊".center(70))
        print("━"*70 + "\n")
        with open(report_path, 'r') as f:
            content = f.read()
            print(content)
        print("\n" + "━"*70)
    else:
        print(f"\n⚠️  Note: evaluation report not found at {report_path}")

def try_plot(m, outpath='output/evaluation_plot.png'):
    try:
        # Force a non-interactive backend to avoid Qt/GUI palette logs on some systems
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
    except Exception as e:
        print('\nmatplotlib not available or failed to initialize — skipping image output. To enable image output install matplotlib and numpy:')
        print('  pip3 install matplotlib numpy')
        return

    TP = float(m.get('TP',0))
    FP = float(m.get('FP',0))
    FN = float(m.get('FN',0))
    TN = float(m.get('TN',0))

    # Bar chart for TP/FP/FN/TN
    labels = ['TP','FP','FN','TN']
    vals = [TP,FP,FN,TN]
    fig, axes = plt.subplots(1,2, figsize=(10,4))
    axes[0].bar(labels, vals, color=['green','red','orange','blue'])
    axes[0].set_title('Confusion counts')
    axes[0].set_ylabel('count')

    # Confusion matrix heatmap
    cm = np.array([[TP, FP],[FN, TN]])
    im = axes[1].imshow(cm, cmap='Blues')
    axes[1].set_xticks([0,1]); axes[1].set_yticks([0,1])
    axes[1].set_xticklabels(['Pred +','Pred -'])
    axes[1].set_yticklabels(['True +','True -'])
    for i in range(2):
        for j in range(2):
            axes[1].text(j, i, int(cm[i,j]), ha='center', va='center', color='black')
    axes[1].set_title('Confusion matrix')
    fig.colorbar(im, ax=axes[1], fraction=0.046, pad=0.04)

    os.makedirs(os.path.dirname(outpath) or '.', exist_ok=True)
    plt.tight_layout()
    plt.savefig(outpath)
    print(f"\nSaved visualization to: {outpath}")

def main():
    if len(sys.argv) < 2:
        path = 'output/evaluation_metrics.csv'
    else:
        path = sys.argv[1]
    if not os.path.exists(path):
        print('Metrics file not found:', path)
        sys.exit(1)
    m = read_metrics(path)
    print_summary(m)
    try_plot(m)

if __name__ == '__main__':
    main()
