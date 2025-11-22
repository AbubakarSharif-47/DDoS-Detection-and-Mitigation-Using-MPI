#define _POSIX_C_SOURCE 200809L
#include "block.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

static char OUTDIR[512] = "output";

typedef struct { char *ip; int rate; time_t ts; } BH;
static BH *list = NULL;
static int nbh = 0;

static void ensure_outdir() {
    struct stat st;
    if (stat(OUTDIR,&st) != 0) {
#ifndef _WIN32
        mkdir(OUTDIR,0755);
#else
        _mkdir(OUTDIR);
#endif
    }
}

void block_init(const char *outdir) {
    if (outdir && outdir[0]) strncpy(OUTDIR, outdir, sizeof(OUTDIR)-1);
    ensure_outdir();
    // clear files
    char p[1024];
    snprintf(p,sizeof(p),"%s/rtbh_blackholes.txt",OUTDIR); FILE *f=fopen(p,"w"); if (f) fclose(f);
    snprintf(p,sizeof(p),"%s/flowspec_rules.txt",OUTDIR); f=fopen(p,"w"); if (f) fclose(f);
    snprintf(p,sizeof(p),"%s/rate_limits.txt",OUTDIR); f=fopen(p,"w"); if (f) fclose(f);
}

void add_blackhole(const char *ip) {
    if (!ip || !*ip) return;
    for (int i=0;i<nbh;i++) if (strcmp(list[i].ip, ip)==0) return;
    list = realloc(list, sizeof(BH)*(nbh+1));
    list[nbh].ip = strdup(ip);
    list[nbh].rate = -1;
    list[nbh].ts = time(NULL);
    nbh++;
    char p[1024]; snprintf(p,sizeof(p),"%s/rtbh_blackholes.txt",OUTDIR);
    FILE *f=fopen(p,"a"); if (f) { fprintf(f,"%s\n", ip); fclose(f); }
}

int is_blackholed(const char *ip) {
    for (int i=0;i<nbh;i++) if (strcmp(list[i].ip, ip)==0) return 1;
    return 0;
}

void generate_flowspec_rule(const char *ip, const char *proto, int port, const char *reason) {
    char p[1024]; snprintf(p,sizeof(p),"%s/flowspec_rules.txt",OUTDIR);
    FILE *f = fopen(p,"a"); if (!f) return;
    time_t t=time(NULL); char ts[64]; strftime(ts,sizeof(ts),"%Y-%m-%d %H:%M:%S", localtime(&t));
    fprintf(f, "# %s\nflow-spec: action deny { src %s", ts, ip);
    if (proto && proto[0]) fprintf(f, "; proto %s", proto);
    if (port>0) fprintf(f, "; dst-port %d", port);
    fprintf(f, " } ; reason=\"%s\"\n\n", reason?reason:"auto");
    fclose(f);
}

void set_rate_limit(const char *ip, int pps) {
    for (int i=0;i<nbh;i++) if (strcmp(list[i].ip, ip)==0) { list[i].rate = pps; break; }
    char p[1024]; snprintf(p,sizeof(p),"%s/rate_limits.txt",OUTDIR);
    FILE *f=fopen(p,"a"); if (!f) return;
    time_t t=time(NULL); char ts[64]; strftime(ts,sizeof(ts),"%Y-%m-%d %H:%M:%S", localtime(&t));
    fprintf(f, "%s: %s -> %d pps\n", ts, ip, pps);
    fclose(f);
}

void block_dump_files(void) { /* files are already written */ }
