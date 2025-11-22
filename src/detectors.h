#ifndef DETECTORS_H
#define DETECTORS_H

#include <stdbool.h>

#define MAX_IP_LEN 64

typedef struct {
    char ip[MAX_IP_LEN];
    long total_packets;
    long total_flows;
    long total_duration;
    int unique_dst_count;
    double mean_packets_per_flow;
    double mean_duration;
    /* windowed entropy stats computed by workers */
    double avg_window_entropy;
    double entropy_trend;
    int window_entropy_count;
} SourceSummary;

typedef struct {
    char ip[MAX_IP_LEN];
    double detection_time;
    double score;
} Alert;

/* initialize/free detectors if needed */
void init_detectors(void);
void free_detectors(void);

/* detectors: input is array of SourceSummary and count
   Each returns allocated Alert array (caller must free) and number via out parameter */
int detect_entropy(SourceSummary *summaries, int n, Alert **alerts_out, int *alerts_n);
int detect_cusum(SourceSummary *summaries, int n, Alert **alerts_out, int *alerts_n);
int detect_pca(SourceSummary *summaries, int n, Alert **alerts_out, int *alerts_n);

/* compute per-source scores for all detectors at once
    Caller allocates arrays of length n (double)
*/
void compute_all_detector_scores(SourceSummary *summaries, int n, double *entropy_scores, double *cusum_scores, double *pca_scores);

/* Threshold variables (can be set via environment variables in init_detectors)
    Declared here so coordinator.c can reference the current thresholds when consolidating votes. */
extern long ENTROPY_MIN_PKTS;
extern double ENTROPY_CONC_THRESHOLD;
extern double CUSUM_DIFF_THRESHOLD;
extern long CUSUM_MIN_PKTS;
extern double PCA_RECON_THRESHOLD;

#endif
