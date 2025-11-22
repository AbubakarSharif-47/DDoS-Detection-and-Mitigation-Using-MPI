#define _POSIX_C_SOURCE 200809L
#include <time.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <mpi.h>
#include <ctype.h>
#include <sys/stat.h>

#include "detectors.h"
#include "block.h"
#include "resource.h"

/* coordinator responsibilities:
   - read standardized CSV (header with required columns)
   - count total lines, then send lines round-robin to workers
   - show progress % while sending
   - after sending, collect per-worker summaries
   - merge summaries into global SourceSummary array
   - run detectors centrally (entropy, cusum, pca)
   - write per-detector alerts and combined malicious/benign lists
   - apply blocking (RTBH + FlowSpec + rate limit logs) for combined malicious
   - write output/results.txt summary (progress, counts)
*/

#define MAX_LINE 8192

typedef struct {
    SourceSummary *arr;
    int n, cap;
} GlobalMap;

static void gmap_init(GlobalMap *m){ m->arr=NULL; m->n=0; m->cap=0; }
static void gmap_free(GlobalMap *m){ if (m->arr) free(m->arr); m->arr=NULL; m->n=0; m->cap=0; }

static SourceSummary *gmap_find(GlobalMap *m, const char *ip) {
    for (int i=0;i<m->n;i++) if (strcmp(m->arr[i].ip, ip)==0) return &m->arr[i];
    return NULL;
}

static SourceSummary *gmap_add(GlobalMap *m, const char *ip) {
    if (m->n == m->cap) {
        int nc = (m->cap==0)? 512 : m->cap*2;
        m->arr = realloc(m->arr, sizeof(SourceSummary)*nc);
        m->cap = nc;
    }
    SourceSummary *s = &m->arr[m->n++];
    memset(s,0,sizeof(SourceSummary));
    strncpy(s->ip, ip, sizeof(s->ip)-1);
    return s;
}

static long count_lines(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    long lines = 0;
    char buf[8192];
    while (fgets(buf, sizeof(buf), f)) lines++;
    fclose(f);
    return lines;
}

// normalize a token: lowercase and remove non-alphanumeric
static void normalize_token(const char *in, char *out, size_t outsz) {
    size_t j = 0;
    for (size_t i = 0; in[i] != '\0' && j+1 < outsz; i++) {
        if (isalnum((unsigned char)in[i])) {
            out[j++] = (char)tolower((unsigned char)in[i]);
        }
    }
    out[j] = '\0';
}

static int find_column_by_variants(char **cols, int ncols, const char **variants, int nvar) {
    char normcol[256];
    char normv[256];
    for (int i = 0; i < ncols; i++) {
        normalize_token(cols[i], normcol, sizeof(normcol));
        for (int j = 0; j < nvar; j++) {
            normalize_token(variants[j], normv, sizeof(normv));
            if (strcmp(normcol, normv) == 0) return i;
        }
    }
    return -1;
}

void coordinator_process(int world_size, const char *csv_path) {
    block_init("output");
    init_detectors();

    FILE *fp = fopen(csv_path, "r");
    if (!fp) { perror("open csv"); return; }

    // count lines to display progress; subtract header
    long total_lines = count_lines(csv_path);
    if (total_lines>0) total_lines -= 1;
    if (total_lines < 0) total_lines = 0;

    // read header to map columns
    char header[MAX_LINE];
    if (!fgets(header, sizeof(header), fp)) { fclose(fp); return; }
    // parse header tokens
    char *cols[64]; int ncols=0;
    char *hcopy = strdup(header);
    char *tk = strtok(hcopy, ",\n\r");
    while (tk && ncols < 64) { cols[ncols++] = strdup(tk); tk = strtok(NULL, ",\n\r"); }
    free(hcopy);
    
    // Column headers found (silently parsed)
    int idx_src=-1, idx_srcport=-1, idx_dst=-1, idx_dstport=-1, idx_proto=-1, idx_ts=-1, idx_duration=-1, idx_fwd=-1, idx_label=-1;

    // Define variants similar to the Python normalizer
    // Note: coordinator.c now expects lowercase headers from to_flows.py (timestamp, src_ip, packets, etc.)
    // But these variant lists also handle other formats for backward compatibility
    const char *v_src[] = {"src_ip","Source IP","source ip","src ip","src","source_ip","source"};
    const char *v_srcport[] = {"src_port","Source Port","source port","src port","sport","source_port"};
    const char *v_dst[] = {"dst_ip","Destination IP","destination ip","dst ip","dst","destination_ip","dest"};
    const char *v_dstport[] = {"dst_port","Destination Port","destination port","dst port","dport","destination_port"};
    const char *v_proto[] = {"protocol","Protocol","proto"};
    const char *v_ts[] = {"timestamp","Timestamp","time","start_time","ts","epoch"};
    const char *v_duration[] = {"duration","Flow Duration","flow duration","flow_duration","flow_length"};
    const char *v_packets[] = {"packets","Total Fwd Packets","total fwd packets","total_fwd_packets","fwd_packets","pkts"};
    const char *v_label[] = {"label","Label","class","attack","is_attack"};

    idx_src = find_column_by_variants(cols, ncols, v_src, sizeof(v_src)/sizeof(v_src[0]));
    idx_srcport = find_column_by_variants(cols, ncols, v_srcport, sizeof(v_srcport)/sizeof(v_srcport[0]));
    idx_dst = find_column_by_variants(cols, ncols, v_dst, sizeof(v_dst)/sizeof(v_dst[0]));
    idx_dstport = find_column_by_variants(cols, ncols, v_dstport, sizeof(v_dstport)/sizeof(v_dstport[0]));
    idx_proto = find_column_by_variants(cols, ncols, v_proto, sizeof(v_proto)/sizeof(v_proto[0]));
    idx_ts = find_column_by_variants(cols, ncols, v_ts, sizeof(v_ts)/sizeof(v_ts[0]));
    idx_duration = find_column_by_variants(cols, ncols, v_duration, sizeof(v_duration)/sizeof(v_duration[0]));
    idx_fwd = find_column_by_variants(cols, ncols, v_packets, sizeof(v_packets)/sizeof(v_packets[0]));
    idx_label = find_column_by_variants(cols, ncols, v_label, sizeof(v_label)/sizeof(v_label[0]));

    if (idx_src<0 || idx_dst<0 || idx_proto<0 || idx_ts<0 || idx_duration<0 || idx_fwd<0) {
        fprintf(stderr,"CSV missing required columns (need Source IP, Destination IP, Protocol, Timestamp, Flow Duration, Total Fwd Packets)\n");
        fprintf(stderr,"  Found: src=%d, dst=%d, proto=%d, ts=%d, duration=%d, fwd=%d\n", idx_src, idx_dst, idx_proto, idx_ts, idx_duration, idx_fwd);
        fclose(fp);
        return;
    }
    // Header mapping successful

    // prepare output directory and files (clear)
    struct stat st = {0};
    if (stat("output", &st) == -1) {
        if (mkdir("output", 0755) != 0) {
            perror("mkdir output");
        }
    }
    char outpath[256];
    snprintf(outpath,sizeof(outpath),"output/results.txt"); FILE *fres=fopen(outpath,"w"); if (fres) fclose(fres);
    snprintf(outpath,sizeof(outpath),"output/entropy_alerts.txt"); FILE *fe=fopen(outpath,"w"); if (fe) fclose(fe);
    snprintf(outpath,sizeof(outpath),"output/cusum_alerts.txt"); FILE *fc=fopen(outpath,"w"); if (fc) fclose(fc);
    snprintf(outpath,sizeof(outpath),"output/pca_alerts.txt"); FILE *fpca=fopen(outpath,"w"); if (fpca) fclose(fpca);
    snprintf(outpath,sizeof(outpath),"output/combined_malicious.txt"); FILE *fm=fopen(outpath,"w"); if (fm) fclose(fm);
    snprintf(outpath,sizeof(outpath),"output/combined_benign.txt"); FILE *fb=fopen(outpath,"w"); if (fb) fclose(fb);

    // Round-robin send lines to workers
    int next = 1;
    char line[MAX_LINE];
    long processed = 0;
    time_t last_print = time(NULL);
    while (fgets(line, sizeof(line), fp)) {
        // parse fields into array to re-order canonical output
            char copy[8192]; strncpy(copy, line, sizeof(copy)-1); copy[sizeof(copy)-1]=0;
            char *fields[64]; int fcount=0;
            // Split by comma but preserve empty fields (strtok collapses consecutive delimiters)
            char *p = copy;
            char *start = copy;
            while (*p && fcount < 64) {
                if (*p == ',' || *p == '\n' || *p == '\r') {
                    *p = '\0';
                    fields[fcount++] = start;
                    start = p + 1;
                }
                p++;
            }
            if (fcount < 64) {
                fields[fcount++] = start;
            }
        if (fcount <= idx_src) continue;
        char out[1024];
        snprintf(out,sizeof(out), "%s,%s,%s,%s,%s,%s,%s,%s,%s",
            fields[idx_src],
            (idx_srcport>=0 && idx_srcport<fcount)?fields[idx_srcport]:"0",
            fields[idx_dst],
            (idx_dstport>=0 && idx_dstport<fcount)?fields[idx_dstport]:"0",
            (idx_proto>=0 && idx_proto<fcount)?fields[idx_proto]:"UNK",
            fields[idx_ts],
            (idx_duration>=0 && idx_duration<fcount)?fields[idx_duration]:"0",
            (idx_fwd>=0 && idx_fwd<fcount)?fields[idx_fwd]:"0",
            (idx_label>=0 && idx_label<fcount)?fields[idx_label]:"0"
        );
        // Debug: print first few rows with their packet values
        // Row processing (silently handled)
        MPI_Send(out, (int)strlen(out)+1, MPI_CHAR, next, 0, MPI_COMM_WORLD);
        processed++;
        next++; if (next == world_size) next = 1;
        // print progress periodically with beautiful formatting
        if (time(NULL) - last_print >= 1) {
            double pct = (total_lines>0) ? (100.0 * (double)processed / (double)total_lines) : 100.0;
            int bar_len = 40;
            int filled = (int)(pct * bar_len / 100.0);
            printf("\r\033[1;36m[Processing]\033[0m [");
            for (int b=0; b<bar_len; b++) printf(b < filled ? "█" : "░");
            printf("] \033[1;33m%.1f%%\033[0m (%ld/%ld flows)", pct, processed, total_lines);
            fflush(stdout);
            last_print = time(NULL);
        }
    }

    // send END to workers
    for (int i=1;i<world_size;i++) MPI_Send("END", 4, MPI_CHAR, i, 0, MPI_COMM_WORLD);

    // collect summaries from workers
    GlobalMap gmap; gmap_init(&gmap);
    int workers_done = 0;
    while (workers_done < world_size-1) {
        char buf[512];
        MPI_Status st;
        MPI_Recv(buf, sizeof(buf), MPI_CHAR, MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &st);
        if (strncmp(buf, "SUMMARY_END",11)==0) { workers_done++; continue; }
        // parse summary line: ip,total_packets,total_flows,total_duration,unique_dst_count,avg_window_entropy,entropy_trend,window_entropy_count
        char ip[128]; long tp=0, tf=0, td=0; int ud=0; double avgH=0.0, trend=0.0; int ecount=0;
        int r = sscanf(buf, "%127[^,],%ld,%ld,%ld,%d,%lf,%lf,%d", ip, &tp, &tf, &td, &ud, &avgH, &trend, &ecount);
        if (r >= 5) {
            SourceSummary *s = gmap_find(&gmap, ip);
            if (!s) s = gmap_add(&gmap, ip);
            s->total_packets += tp;
            s->total_flows += tf;
            s->total_duration += td;
            s->unique_dst_count += ud;
            if (r >= 8) {
                s->avg_window_entropy = avgH;
                s->entropy_trend = trend;
                s->window_entropy_count = ecount;
            } else {
                s->avg_window_entropy = 0.0;
                s->entropy_trend = 0.0;
                s->window_entropy_count = 0;
            }
        }
    }

    // finalize per-source stats
    for (int i=0;i<gmap.n;i++) {
        if (gmap.arr[i].total_flows > 0) {
            gmap.arr[i].mean_packets_per_flow = (double)gmap.arr[i].total_packets / (double)gmap.arr[i].total_flows;
            gmap.arr[i].mean_duration = (double)gmap.arr[i].total_duration / (double)gmap.arr[i].total_flows;
        } else {
            gmap.arr[i].mean_packets_per_flow = 0.0;
            gmap.arr[i].mean_duration = 0.0;
        }
    }

    // compute per-IP detector scores and write to CSV for debugging/insight
    double *entropy_scores = NULL;
    double *cusum_scores = NULL;
    double *pca_scores = NULL;
    if (gmap.n > 0) {
        entropy_scores = calloc(gmap.n, sizeof(double));
        cusum_scores = calloc(gmap.n, sizeof(double));
        pca_scores = calloc(gmap.n, sizeof(double));
        compute_all_detector_scores(gmap.arr, gmap.n, entropy_scores, cusum_scores, pca_scores);
        FILE *fs = fopen("output/detector_scores.csv","w");
        if (fs) {
            fprintf(fs, "ip,entropy_score,cusum_score,pca_score,total_packets,total_flows\n");
            for (int i=0;i<gmap.n;i++) {
                fprintf(fs, "%s,%.6f,%.6f,%.6f,%ld,%ld\n",
                    gmap.arr[i].ip,
                    entropy_scores[i],
                    cusum_scores[i],
                    pca_scores[i],
                    gmap.arr[i].total_packets,
                    gmap.arr[i].total_flows);
            }
            fclose(fs);
        }
    }

    // run detectors centrally
    Alert *a_entropy=NULL; int n_entropy=0;
    Alert *a_cusum=NULL; int n_cusum=0;
    Alert *a_pca=NULL; int n_pca=0;

    detect_entropy(gmap.arr, gmap.n, &a_entropy, &n_entropy);
    detect_cusum(gmap.arr, gmap.n, &a_cusum, &n_cusum);
    detect_pca(gmap.arr, gmap.n, &a_pca, &n_pca);

    // write per-detector files
    FILE *f_ent = fopen("output/entropy_alerts.txt","w");
    for (int i=0;i<n_entropy;i++) fprintf(f_ent, "%s,%.6f,%.6f\n", a_entropy[i].ip, a_entropy[i].detection_time, a_entropy[i].score);
    if (f_ent) fclose(f_ent);

    FILE *f_cus = fopen("output/cusum_alerts.txt","w");
    for (int i=0;i<n_cusum;i++) fprintf(f_cus, "%s,%.6f,%.6f\n", a_cusum[i].ip, a_cusum[i].detection_time, a_cusum[i].score);
    if (f_cus) fclose(f_cus);

    FILE *f_p = fopen("output/pca_alerts.txt","w");
    for (int i=0;i<n_pca;i++) fprintf(f_p, "%s,%.6f,%.6f\n", a_pca[i].ip, a_pca[i].detection_time, a_pca[i].score);
    if (f_p) fclose(f_p);

    // consolidate ensemble: require configurable number of detectors (ENSEMBLE_MIN)
    int combined_count = 0;
    int ensemble_min = 1;
    {
        const char *ev = getenv("ENSEMBLE_MIN");
        if (ev) ensemble_min = atoi(ev);
        if (ensemble_min < 1) ensemble_min = 1;
    }
    // compute total packets for percent calculations
    long total_packets_sum = 0;
    for (int i=0;i<gmap.n;i++) total_packets_sum += gmap.arr[i].total_packets;

    long malicious_packets_sum = 0;
    printf("\n\033[1;32m╔════════════════════════════════════╗\033[0m\n");
    printf("\033[1;32m║  🔍 Detection Results 🔍       ║\033[0m\n");
    printf("\033[1;32m╚════════════════════════════════════╝\033[0m\n");
    printf("Evaluating \033[1;36m%d\033[0m unique source IPs | Threshold: \033[1;33m%d detector(s)\033[0m\n\n", gmap.n, ensemble_min);
    FILE *verbose_log = fopen("output/detection_log.txt","w");
    
    for (int i=0;i<gmap.n;i++) {
        int votes = 0;
        // entropy vote
        int entropy_vote = 0;
        if (entropy_scores && gmap.arr[i].total_packets > ENTROPY_MIN_PKTS && entropy_scores[i] >= ENTROPY_CONC_THRESHOLD) { votes++; entropy_vote=1; }
        // cusum vote
        int cusum_vote = 0;
        if (cusum_scores && gmap.arr[i].total_packets > CUSUM_MIN_PKTS && cusum_scores[i] > CUSUM_DIFF_THRESHOLD) { votes++; cusum_vote=1; }
        // pca vote
        int pca_vote = 0;
        if (pca_scores && pca_scores[i] > PCA_RECON_THRESHOLD) { votes++; pca_vote=1; }

        // Print scores for flagged IPs with colorful output
        if (votes > 0) {
            const char *threat_color = (votes >= ensemble_min) ? "\033[1;31m" : "\033[1;33m";
            printf("%sIP: %-15s\033[0m | pkts=\033[1;36m%6ld\033[0m flows=\033[1;36m%5ld\033[0m | "
                   "entropy=\033[1;35m%.2f\033[0m(%d) cusum=\033[1;35m%.2f\033[0m(%d) pca=\033[1;35m%.2e\033[0m(%d) | votes=\033[1;31m%d\033[0m\n",
                threat_color, gmap.arr[i].ip, gmap.arr[i].total_packets, gmap.arr[i].total_flows,
                entropy_scores ? entropy_scores[i] : 0.0, entropy_vote,
                cusum_scores ? cusum_scores[i] : 0.0, cusum_vote,
                pca_scores ? pca_scores[i] : 0.0, pca_vote,
                votes);
            if (verbose_log) {
                fprintf(verbose_log, "%s,%ld,%ld,%.6f,%d,%.6f,%d,%.6e,%d,%d\n",
                    gmap.arr[i].ip, gmap.arr[i].total_packets, gmap.arr[i].total_flows,
                    entropy_scores ? entropy_scores[i] : 0.0, entropy_vote,
                    cusum_scores ? cusum_scores[i] : 0.0, cusum_vote,
                    pca_scores ? pca_scores[i] : 0.0, pca_vote,
                    votes);
            }
        }

        if (votes >= ensemble_min) {
            FILE *fm = fopen("output/combined_malicious.txt","a");
            if (fm) {
                fprintf(fm, "%s,%ld,%ld\n", gmap.arr[i].ip, gmap.arr[i].total_packets, gmap.arr[i].total_flows);
                fclose(fm);
            }
            combined_count++;
            malicious_packets_sum += gmap.arr[i].total_packets;
            // apply blocking
            add_blackhole(gmap.arr[i].ip);
            generate_flowspec_rule(gmap.arr[i].ip, "ANY", 0, "detected-by-ensemble");
            set_rate_limit(gmap.arr[i].ip, 1000);
        } else {
            FILE *fb = fopen("output/combined_benign.txt","a");
            if (fb) {
                fprintf(fb, "%s,%ld,%ld\n", gmap.arr[i].ip, gmap.arr[i].total_packets, gmap.arr[i].total_flows);
                fclose(fb);
            }
        }
    }
    if (verbose_log) fclose(verbose_log);
    printf("\n\033[1;32m╔════════════════════════════════════╗\033[0m\n");
    printf("\033[1;32m║   📊 Summary 📊                ║\033[0m\n");
    printf("\033[1;32m╚════════════════════════════════════╝\033[0m\n");
    printf("  Total IPs:              \033[1;36m%d\033[0m\n", gmap.n);
    printf("  🚨 Malicious IPs:       \033[1;31m%d\033[0m\n", combined_count);
    printf("  📈 Malicious packets:   \033[1;31m%ld\033[0m / \033[1;36m%ld\033[0m\n\n", malicious_packets_sum, total_packets_sum);

    // write attack summary (unsupervised result) with percentages and decision
    double malicious_ip_pct = 0.0;
    double malicious_packets_pct = 0.0;
    if (gmap.n > 0) malicious_ip_pct = 100.0 * (double)combined_count / (double)gmap.n;
    if (total_packets_sum > 0) malicious_packets_pct = 100.0 * (double)malicious_packets_sum / (double)total_packets_sum;
    double ddos_threshold = 1.0; // percent
    const char *td = getenv("DDOS_PACKET_PCT_THRESHOLD");
    if (td) ddos_threshold = atof(td);
    int ddos_detected = (malicious_packets_pct >= ddos_threshold) ? 1 : 0;
    FILE *fas = fopen("output/attack_summary.txt","w");
    if (fas) {
        fprintf(fas, "malicious_ip_count=%d\n", combined_count);
        fprintf(fas, "total_ips=%d\n", gmap.n);
        fprintf(fas, "malicious_ip_pct=%.6f\n", malicious_ip_pct);
        fprintf(fas, "malicious_packets=%ld\n", malicious_packets_sum);
        fprintf(fas, "total_packets=%ld\n", total_packets_sum);
        fprintf(fas, "malicious_packets_pct=%.6f\n", malicious_packets_pct);
        fprintf(fas, "ddos_threshold_pct=%.6f\n", ddos_threshold);
        fprintf(fas, "ddos_detected=%d\n", ddos_detected);
        fclose(fas);
    }

    // write high-level results.txt
    FILE *res = fopen("output/results.txt","w");
    if (res) {
        fprintf(res, "processed_flows=%ld\n", total_lines);
        fprintf(res, "detected_entropy=%d\n", n_entropy);
        fprintf(res, "detected_cusum=%d\n", n_cusum);
        fprintf(res, "detected_pca=%d\n", n_pca);
        fprintf(res, "combined_malicious_count=%d\n", combined_count);
        fclose(res);
    }

    // write runtime resource stats for evaluation phase
    write_resource_stats("output/resource_stats.txt", csv_path);

    // clean
    if (a_entropy) free(a_entropy);
    if (a_cusum) free(a_cusum);
    if (a_pca) free(a_pca);

    // free score arrays
    if (entropy_scores) free(entropy_scores);
    if (cusum_scores) free(cusum_scores);
    if (pca_scores) free(pca_scores);

    gmap_free(&gmap);
    free_detectors();
    fclose(fp);
}
