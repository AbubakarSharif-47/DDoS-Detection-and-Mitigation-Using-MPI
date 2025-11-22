#define _POSIX_C_SOURCE 200809L
#include "resource.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#ifdef __linux__
#include <unistd.h>
#endif

static int read_cpu_totals(unsigned long long *idle, unsigned long long *total) {
#ifdef __linux__
    FILE *f = fopen("/proc/stat", "r");
    if (!f) return -1;
    char line[256];
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    unsigned long long user, nice, system, idle_v, iowait, irq, softirq, steal, guest, guest_nice;
    int parsed = sscanf(line, "cpu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
                        &user, &nice, &system, &idle_v, &iowait, &irq, &softirq, &steal, &guest, &guest_nice);
    if (parsed < 4) return -1;
    *idle = idle_v + iowait;
    *total = user + nice + system + idle_v + iowait + irq + softirq + steal + guest + guest_nice;
    return 0;
#else
    (void)idle; (void)total;
    return -1;
#endif
}

static int read_net_totals(unsigned long long *rx, unsigned long long *tx) {
#ifdef __linux__
    FILE *f = fopen("/proc/net/dev", "r");
    if (!f) return -1;
    char line[512];
    // skip headers
    fgets(line, sizeof(line), f);
    fgets(line, sizeof(line), f);
    unsigned long long rx_total = 0;
    unsigned long long tx_total = 0;
    while (fgets(line, sizeof(line), f)) {
        char iface[64];
        unsigned long long rx_bytes, tx_bytes;
        int matched = sscanf(line, " %63[^:]: %llu %*u %*u %*u %*u %*u %*u %*u %llu",
                             iface, &rx_bytes, &tx_bytes);
        if (matched == 2) {
            rx_total += rx_bytes;
            tx_total += tx_bytes;
        }
    }
    fclose(f);
    *rx = rx_total;
    *tx = tx_total;
    return 0;
#else
    (void)rx; (void)tx;
    return -1;
#endif
}

static int read_meminfo(double *total_mb, double *used_mb, double *percent) {
#ifdef __linux__
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return -1;
    char line[256];
    double mem_total_kb = 0.0;
    double mem_available_kb = 0.0;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "MemTotal: %lf kB", &mem_total_kb) == 1) continue;
        if (sscanf(line, "MemAvailable: %lf kB", &mem_available_kb) == 1) continue;
    }
    fclose(f);
    if (mem_total_kb <= 0.0) return -1;
    double used_kb = mem_total_kb - mem_available_kb;
    *total_mb = mem_total_kb / 1024.0;
    *used_mb = used_kb / 1024.0;
    *percent = (*total_mb > 0.0) ? (100.0 * (*used_mb) / (*total_mb)) : 0.0;
    return 0;
#else
    (void)total_mb; (void)used_mb; (void)percent;
    return -1;
#endif
}

int collect_resource_stats(ResourceStats *stats) {
    if (!stats) return -1;
    memset(stats, 0, sizeof(ResourceStats));
    strcpy(stats->gpu_percent, "N/A");
#ifdef __linux__
    const double interval_sec = 0.5;
    unsigned long long idle1=0,total1=0,idle2=0,total2=0;
    unsigned long long rx1=0,tx1=0,rx2=0,tx2=0;
    if (read_cpu_totals(&idle1,&total1)!=0) return -1;
    read_net_totals(&rx1,&tx1);
    struct timespec req; req.tv_sec = 0; req.tv_nsec = (long)(interval_sec * 1e9);
    nanosleep(&req, NULL);
    if (read_cpu_totals(&idle2,&total2)!=0) return -1;
    read_net_totals(&rx2,&tx2);
    unsigned long long total_delta = (total2 > total1) ? (total2 - total1) : 0;
    unsigned long long idle_delta = (idle2 > idle1) ? (idle2 - idle1) : 0;
    if (total_delta > 0) {
        stats->cpu_percent = 100.0 * (double)(total_delta - idle_delta) / (double)total_delta;
    } else {
        stats->cpu_percent = 0.0;
    }
    double total_mb=0.0, used_mb=0.0, mem_pct=0.0;
    if (read_meminfo(&total_mb,&used_mb,&mem_pct)==0) {
        stats->mem_total_mb = total_mb;
        stats->mem_used_mb = used_mb;
        stats->mem_percent = mem_pct;
    }
    double bytes_delta = (double)((rx2 - rx1) + (tx2 - tx1));
    stats->net_mbps = (interval_sec > 0.0) ? ((bytes_delta * 8.0) / (interval_sec * 1000000.0)) : 0.0;
    return 0;
#else
    return -1;
#endif
}

int write_resource_stats(const char *outpath, const char *input_csv) {
    ResourceStats stats;
    int rc = collect_resource_stats(&stats);
    FILE *f = fopen(outpath, "w");
    if (!f) return -1;
    time_t now = time(NULL);
    fprintf(f, "timestamp=%ld\n", (long)now);
    if (input_csv) fprintf(f, "input_file=%s\n", input_csv);
    if (rc == 0) {
        fprintf(f, "cpu_percent=%.2f\n", stats.cpu_percent);
        fprintf(f, "mem_used_mb=%.2f\n", stats.mem_used_mb);
        fprintf(f, "mem_total_mb=%.2f\n", stats.mem_total_mb);
        fprintf(f, "mem_percent=%.2f\n", stats.mem_percent);
        fprintf(f, "net_rate_mbps=%.4f\n", stats.net_mbps);
        fprintf(f, "gpu_percent=%s\n", stats.gpu_percent);
    } else {
        fprintf(f, "cpu_percent=N/A\n");
        fprintf(f, "mem_used_mb=N/A\n");
        fprintf(f, "mem_total_mb=N/A\n");
        fprintf(f, "mem_percent=N/A\n");
        fprintf(f, "net_rate_mbps=N/A\n");
        fprintf(f, "gpu_percent=N/A\n");
    }
    fclose(f);
    return 0;
}

