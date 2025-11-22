#define _POSIX_C_SOURCE 200809L
#include <mpi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>

#include "detectors.h"

/* Worker aggregates per-source summary and sends summaries to coordinator when done.
   Coordinator sends lines (canonical order) to workers. Worker expects canonical CSV line:
   src,srcport,dst,dstport,proto,ts,duration,fwd_pkts,label
*/

typedef struct {
    SourceSummary *arr;
    int n, cap;
    char **dst_samples; // not used fully; we approximate unique dst count
    /* per-source sliding window buffers and entropy lists */
    char ***win_bufs; /* per-src: array of char* of length WINDOW_SIZE */
    int *win_pos;     /* current position in window for each src */
    double **ent_vals; /* per-src dynamic array of entropy values */
    int *ent_n;        /* per-src entropy count */
    int *ent_cap;      /* per-src entropy capacity */
} SummMap;

static void map_init(SummMap *m) {
    m->arr = NULL;
    m->n = 0;
    m->cap = 0;
    m->dst_samples = NULL;
    m->win_bufs = NULL;
    m->win_pos = NULL;
    m->ent_vals = NULL;
    m->ent_n = NULL;
    m->ent_cap = NULL;
}
static void map_free(SummMap *m) {
    if (m->arr) free(m->arr);
    if (m->dst_samples) { for (int i=0;i<m->n;i++) if (m->dst_samples[i]) free(m->dst_samples[i]); free(m->dst_samples);}
    if (m->win_bufs) {
        for (int i=0;i<m->n;i++) {
            if (m->win_bufs[i]) {
                for (int j=0;j<100;j++) if (m->win_bufs[i][j]) free(m->win_bufs[i][j]);
                free(m->win_bufs[i]);
            }
        }
        free(m->win_bufs);
    }
    if (m->win_pos) free(m->win_pos);
    if (m->ent_vals) {
        for (int i=0;i<m->n;i++) if (m->ent_vals[i]) free(m->ent_vals[i]);
        free(m->ent_vals);
    }
    if (m->ent_n) free(m->ent_n);
    if (m->ent_cap) free(m->ent_cap);
    m->arr=NULL; m->dst_samples=NULL; m->win_bufs=NULL; m->win_pos=NULL; m->ent_vals=NULL; m->ent_n=NULL; m->ent_cap=NULL; m->n=0; m->cap=0;
}

static SourceSummary *map_find(SummMap *m, const char *ip) {
    for (int i=0;i<m->n;i++) if (strcmp(m->arr[i].ip, ip)==0) return &m->arr[i];
    return NULL;
}
static SourceSummary *map_add(SummMap *m, const char *ip) {
    if (m->n == m->cap) {
        int nc = (m->cap==0) ? 256 : m->cap*2;
        m->arr = realloc(m->arr, sizeof(SourceSummary)*nc);
        m->dst_samples = realloc(m->dst_samples, sizeof(char*)*nc);
        m->win_bufs = realloc(m->win_bufs, sizeof(char**)*nc);
        m->win_pos = realloc(m->win_pos, sizeof(int)*nc);
        m->ent_vals = realloc(m->ent_vals, sizeof(double*)*nc);
        m->ent_n = realloc(m->ent_n, sizeof(int)*nc);
        m->ent_cap = realloc(m->ent_cap, sizeof(int)*nc);
        for (int i=m->cap;i<nc;i++) {
            m->dst_samples[i]=NULL;
            m->win_bufs[i]=NULL;
            m->win_pos[i]=0;
            m->ent_vals[i]=NULL;
            m->ent_n[i]=0;
            m->ent_cap[i]=0;
        }
        m->cap = nc;
    }
    SourceSummary *s = &m->arr[m->n];
    memset(s,0,sizeof(SourceSummary));
    strncpy(s->ip, ip, sizeof(s->ip)-1);
    s->unique_dst_count = 0;
    m->dst_samples[m->n] = NULL;
    /* allocate window buffer on demand when first used */
    m->win_bufs[m->n] = NULL;
    m->n++;
    return s;
}

/* simple check if dst seen before for this src index */
static int sample_add_dst(SummMap *m, int idx, const char *dst) {
    if (!m->dst_samples[idx]) {
        m->dst_samples[idx] = strdup(dst);
        return 1;
    }
    if (strcmp(m->dst_samples[idx], dst) != 0) {
        /* we approximate uniqueness by counting different last seen only */
        free(m->dst_samples[idx]);
        m->dst_samples[idx] = strdup(dst);
        return 1;
    }
    return 0;
}

void worker_process(int rank) {
    SummMap map; map_init(&map);
    char buf[4096];
    MPI_Status st;
    while (1) {
        MPI_Recv(buf, sizeof(buf), MPI_CHAR, 0, MPI_ANY_TAG, MPI_COMM_WORLD, &st);
        if (strcmp(buf, "END")==0) break;
        // parse canonical CSV (9 fields)
        char copy[4096]; strncpy(copy, buf, sizeof(copy)-1); copy[sizeof(copy)-1]=0;
        char *f[12]; int fc=0;
        char *tk = strtok(copy, ",\n\r");
        while (tk && fc<12) { f[fc++] = tk; tk = strtok(NULL, ",\n\r"); }
        if (fc < 8) continue;
        const char *src = f[0];
        const char *dst = f[2];
        int fwd_pkts = atoi(f[7]);
        long duration = atol(f[6]);
        // find or add src
        SourceSummary *s = map_find(&map, src);
        int idx=-1;
        if (!s) { s = map_add(&map, src); idx = map.n-1; } else {
            for (int i=0;i<map.n;i++) if (strcmp(map.arr[i].ip, src)==0) { idx=i; break; }
        }
        if (idx<0) { idx=0; } // safety
        s->total_flows += 1;
        s->total_packets += fwd_pkts;
        s->total_duration += duration;
        if (sample_add_dst(&map, idx, dst)) s->unique_dst_count += 1;
        /* WINDOW handling: collect dst into per-src window buffer of size 100 (non-overlapping windows)
           when full, compute Shannon entropy over destination distribution, append to ent_vals
        */
        const int WINDOW = 100;
        if (!map.win_bufs[idx]) {
            map.win_bufs[idx] = calloc(WINDOW, sizeof(char*));
            map.win_pos[idx] = 0;
        }
        /* store copy of dst */
        if (map.win_bufs[idx][map.win_pos[idx]]) free(map.win_bufs[idx][map.win_pos[idx]]);
        map.win_bufs[idx][map.win_pos[idx]] = strdup(dst);
        map.win_pos[idx]++;
        if (map.win_pos[idx] >= WINDOW) {
            /* compute frequency counts */
            int counts[WINDOW]; char *vals[WINDOW]; int uniq=0;
            for (int a=0;a<WINDOW;a++) { counts[a]=0; vals[a]=map.win_bufs[idx][a]; }
            for (int a=0;a<WINDOW;a++) {
                if (!vals[a]) continue;
                int found=-1;
                for (int b=0;b<uniq;b++) if (strcmp(vals[a], vals[b])==0) { found=b; break; }
                if (found==-1) { vals[uniq]=vals[a]; counts[uniq]=1; uniq++; }
                else counts[found]++;
            }
            /* compute Shannon entropy on scale 0-100
               With WINDOW=100 flows, max entropy is log2(100)~6.64 (all unique destinations)
               We scale to 0-100: H_scaled = (H / log2(100)) * 100
               High entropy (70-100) = many unique targets = suspicious DDoS behavior
            */
            double H=0.0;
            for (int a=0;a<uniq;a++) {
                double p = (double)counts[a] / (double)WINDOW;
                if (p>0) H -= p * log2(p);
            }
            double H_scaled = (H / log2(100.0)) * 100.0;
            /* append to ent_vals */
            if (map.ent_n[idx] + 1 > map.ent_cap[idx]) {
                int nc = (map.ent_cap[idx]==0)?8:map.ent_cap[idx]*2;
                map.ent_vals[idx] = realloc(map.ent_vals[idx], sizeof(double)*nc);
                map.ent_cap[idx] = nc;
            }
            map.ent_vals[idx][map.ent_n[idx]++] = H_scaled;
            /* reset window buffer */
            for (int a=0;a<WINDOW;a++) { free(map.win_bufs[idx][a]); map.win_bufs[idx][a]=NULL; }
            map.win_pos[idx]=0;
        }
    }

    // send summaries to coordinator: one line per source: ip,total_packets,total_flows,total_duration,unique_dst_count
    for (int i=0;i<map.n;i++) {
        char out[256];
        SourceSummary *s = &map.arr[i];
        /* compute avg entropy and trend */
        double avgH = 0.0, trend = 0.0;
        int ec = map.ent_n[i];
        if (ec > 0) {
            double sum = 0.0;
            for (int j=0;j<ec;j++) sum += map.ent_vals[i][j];
            avgH = sum / (double)ec;
            if (ec > 1) {
                /* simple slope: (last - first) / (ec-1) */
                trend = (map.ent_vals[i][ec-1] - map.ent_vals[i][0]) / (double)(ec-1);
            } else trend = 0.0;
        }
        s->avg_window_entropy = avgH;
        s->entropy_trend = trend;
        s->window_entropy_count = ec;
        snprintf(out,sizeof(out), "%s,%ld,%ld,%ld,%d,%.6f,%.6f,%d", s->ip, s->total_packets, s->total_flows, s->total_duration, s->unique_dst_count, s->avg_window_entropy, s->entropy_trend, s->window_entropy_count);
        MPI_Send(out, (int)strlen(out)+1, MPI_CHAR, 0, 0, MPI_COMM_WORLD);
    }
    MPI_Send("SUMMARY_END", 12, MPI_CHAR, 0, 0, MPI_COMM_WORLD);
    map_free(&map);
}
