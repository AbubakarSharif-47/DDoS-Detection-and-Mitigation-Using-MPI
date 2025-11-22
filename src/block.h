#ifndef BLOCK_H
#define BLOCK_H

void block_init(const char *outdir);
void add_blackhole(const char *ip);
int is_blackholed(const char *ip);
void generate_flowspec_rule(const char *ip, const char *proto, int port, const char *reason);
void set_rate_limit(const char *ip, int pps);
void block_dump_files(void);

#endif
