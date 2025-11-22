#ifndef RESOURCE_H
#define RESOURCE_H

typedef struct {
    double cpu_percent;
    double mem_used_mb;
    double mem_total_mb;
    double mem_percent;
    double net_mbps;
    char gpu_percent[32];
} ResourceStats;

int collect_resource_stats(ResourceStats *stats);
int write_resource_stats(const char *outpath, const char *input_csv);

#endif

