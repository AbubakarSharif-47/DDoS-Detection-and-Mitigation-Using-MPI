#define _POSIX_C_SOURCE 200809L
#include "detectors.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <time.h>

/* simple placeholders for init/free */
/* configurable thresholds (can be overridden via environment variables) */
long ENTROPY_MIN_PKTS = 10;
double ENTROPY_CONC_THRESHOLD = 5.0;
double CUSUM_DIFF_THRESHOLD = 5.0;
long CUSUM_MIN_PKTS = 1;
double PCA_RECON_THRESHOLD = 1e4;

void init_detectors(void) {
    const char *s;
    s = getenv("ENTROPY_MIN_PKTS"); if (s) ENTROPY_MIN_PKTS = atol(s);
    s = getenv("ENTROPY_CONC_THRESHOLD"); if (s) ENTROPY_CONC_THRESHOLD = atof(s);
    s = getenv("CUSUM_DIFF_THRESHOLD"); if (s) CUSUM_DIFF_THRESHOLD = atof(s);
    s = getenv("CUSUM_MIN_PKTS"); if (s) CUSUM_MIN_PKTS = atol(s);
    s = getenv("PCA_RECON_THRESHOLD"); if (s) PCA_RECON_THRESHOLD = atof(s);
}
void free_detectors(void) { }

/* entropy-like detector using unique_dst_count and total_packets heuristic */
int detect_entropy(SourceSummary *summaries, int n, Alert **alerts_out, int *alerts_n) {
    if (n<=0) { *alerts_out = NULL; *alerts_n = 0; return 0; }
    Alert *alerts = malloc(sizeof(Alert) * n);
    int a = 0;
    for (int i=0;i<n;i++) {
        /* Use windowed average entropy (0-100 scale).
           High entropy (close to 100) = many unique destination IPs = DDoS scanning behavior.
           Only consider sources with at least one full window computed. */
        double H = -1.0;
        if (summaries[i].window_entropy_count > 0) {
            H = summaries[i].avg_window_entropy;
        }
        /* Flag IPs with high avg window entropy (>= threshold, e.g., 70) as malicious */
        if (summaries[i].total_packets > ENTROPY_MIN_PKTS && H >= 0.0 && H >= ENTROPY_CONC_THRESHOLD) {
            strncpy(alerts[a].ip, summaries[i].ip, sizeof(alerts[a].ip)-1);
            alerts[a].detection_time = (double)time(NULL);
            alerts[a].score = H;
            a++;
        }
    }
    *alerts_out = alerts; *alerts_n = a;
    return a;
}

/* simple cusum-style detector using mean_packets_per_flow vs global mean */
int detect_cusum(SourceSummary *summaries, int n, Alert **alerts_out, int *alerts_n) {
    if (n<=0) { *alerts_out=NULL; *alerts_n=0; return 0; }
    double sum = 0.0;
    for (int i=0;i<n;i++) sum += summaries[i].mean_packets_per_flow;
    double global_mean = sum / (double)n;
    Alert *alerts = malloc(sizeof(Alert) * n);
    int a=0;
    for (int i=0;i<n;i++) {
        double diff = summaries[i].mean_packets_per_flow - global_mean;
        if (diff > CUSUM_DIFF_THRESHOLD && summaries[i].total_packets > CUSUM_MIN_PKTS) {
            strncpy(alerts[a].ip, summaries[i].ip, sizeof(alerts[a].ip)-1);
            alerts[a].detection_time = (double)time(NULL);
            alerts[a].score = diff;
            a++;
        }
    }
    *alerts_out = alerts; *alerts_n = a;
    return a;
}

/* PCA-like detector: 5-feature vector, power iteration for principal component, reconstruction error */
int detect_pca(SourceSummary *summaries, int n, Alert **alerts_out, int *alerts_n) {
    if (n<=0) { *alerts_out=NULL; *alerts_n=0; return 0; }
    const int D = 5;
    double *M = calloc(n*D, sizeof(double));
    for (int i=0;i<n;i++) {
        M[i*D+0] = (double)summaries[i].total_packets;
        M[i*D+1] = (double)summaries[i].total_flows;
        M[i*D+2] = summaries[i].mean_packets_per_flow;
        M[i*D+3] = summaries[i].mean_duration;
        M[i*D+4] = (double)summaries[i].unique_dst_count;
    }
    // column means
    double mu[D]; for (int d=0;d<D;d++) { double s=0.0; for (int i=0;i<n;i++) s += M[i*D+d]; mu[d]=s/n; }
    // center
    for (int i=0;i<n;i++) for (int d=0;d<D;d++) M[i*D+d] -= mu[d];
    // covariance
    double C[D*D]; memset(C,0,sizeof(C));
    for (int i=0;i<n;i++) for (int p=0;p<D;p++) for (int q=0;q<D;q++) C[p*D+q] += M[i*D+p]*M[i*D+q];
    double denom = (n>1) ? (double)(n-1) : 1.0;
    for (int i=0;i<D*D;i++) C[i] /= denom;
    // power iteration
    double v[D]; for (int d=0;d<D;d++) v[d]=1.0;
    for (int it=0; it<50; it++) {
        double w[D]; memset(w,0,sizeof(w));
        for (int i=0;i<D;i++) for (int j=0;j<D;j++) w[i] += C[i*D+j] * v[j];
        double norm=0; for (int i=0;i<D;i++) norm += w[i]*w[i]; norm = sqrt(norm);
        if (norm == 0) break;
        for (int i=0;i<D;i++) v[i] = w[i]/norm;
    }
    Alert *alerts = malloc(sizeof(Alert) * n);
    int a=0;
    for (int i=0;i<n;i++) {
        double proj=0; for (int d=0;d<D;d++) proj += M[i*D+d] * v[d];
        double recon_err=0; for (int d=0;d<D;d++) { double diff = M[i*D+d] - proj*v[d]; recon_err += diff*diff; }
        if (recon_err > PCA_RECON_THRESHOLD) {
            strncpy(alerts[a].ip, summaries[i].ip, sizeof(alerts[a].ip)-1);
            alerts[a].detection_time = (double)time(NULL);
            alerts[a].score = recon_err;
            a++;
        }
    }
    free(M);
    *alerts_out = alerts; *alerts_n = a;
    return a;
}

/* compute per-source scores for all detectors at once */
void compute_all_detector_scores(SourceSummary *summaries, int n, double *entropy_scores, double *cusum_scores, double *pca_scores) {
    if (n<=0) return;
    // entropy-style score (0-100 scale: high entropy = suspicious)
    for (int i=0;i<n;i++) {
        /* Use avg window entropy where available; fallback to 0 (low entropy) if not present */
        if (summaries[i].window_entropy_count > 0) entropy_scores[i] = summaries[i].avg_window_entropy;
        else {
            /* no window data: set to 0 so it's not flagged as malicious */
            entropy_scores[i] = 0.0;
        }
    }
    // cusum-style: compute global mean
    double sum = 0.0;
    for (int i=0;i<n;i++) sum += summaries[i].mean_packets_per_flow;
    double global_mean = sum / (double)n;
    for (int i=0;i<n;i++) {
        cusum_scores[i] = summaries[i].mean_packets_per_flow - global_mean;
    }
    // PCA-style: replicate compute from detect_pca to get recon_err per source
    const int D = 5;
    double *M = calloc(n*D, sizeof(double));
    for (int i=0;i<n;i++) {
        M[i*D+0] = (double)summaries[i].total_packets;
        M[i*D+1] = (double)summaries[i].total_flows;
        M[i*D+2] = summaries[i].mean_packets_per_flow;
        M[i*D+3] = summaries[i].mean_duration;
        M[i*D+4] = (double)summaries[i].unique_dst_count;
    }
    double mu[D]; for (int d=0;d<D;d++) { double s=0.0; for (int i=0;i<n;i++) s += M[i*D+d]; mu[d]=s/n; }
    for (int i=0;i<n;i++) for (int d=0;d<D;d++) M[i*D+d] -= mu[d];
    double C[D*D]; memset(C,0,sizeof(C));
    for (int i=0;i<n;i++) for (int p=0;p<D;p++) for (int q=0;q<D;q++) C[p*D+q] += M[i*D+p]*M[i*D+q];
    double denom = (n>1) ? (double)(n-1) : 1.0;
    for (int i=0;i<D*D;i++) C[i] /= denom;
    double v[D]; for (int d=0;d<D;d++) v[d]=1.0;
    for (int it=0; it<50; it++) {
        double w[D]; memset(w,0,sizeof(w));
        for (int i=0;i<D;i++) for (int j=0;j<D;j++) w[i] += C[i*D+j] * v[j];
        double norm=0; for (int i=0;i<D;i++) norm += w[i]*w[i]; norm = sqrt(norm);
        if (norm == 0) break;
        for (int i=0;i<D;i++) v[i] = w[i]/norm;
    }
    for (int i=0;i<n;i++) {
        double proj=0; for (int d=0;d<D;d++) proj += M[i*D+d] * v[d];
        double recon_err=0; for (int d=0;d<D;d++) { double diff = M[i*D+d] - proj*v[d]; recon_err += diff*diff; }
        pca_scores[i] = recon_err;
    }
    free(M);
}
