// SPDX-License-Identifier: GPL-2.0 or MIT

#include "common.h"

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_link.h>
#include <net/if.h>

#include <sys/time.h>
#include <sys/resource.h>

#include <libubus.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>

#include <include/bpf_util.h>

#define PROG_NAME "xdpnetload"

#define DEBUG 1

#if defined(DEBUG) && DEBUG > 0
#define dprint(fmt, args...) fprintf(stderr, "DEBUG: %s:%d:%s(): " fmt, \
                                      __FILE__, __LINE__, __func__, ##args)
#else
#define dprint(fmt, args...)
#endif

static unsigned int verbose = 0;
static struct timeval log_interval = {1, 0};

static const char *opts = "SNvhi:";
static struct option lopts[] = {
        { "xdp-skb", no_argument, NULL, 'S'},
        { "xdb-native", no_argument, NULL, 'N'},
        { "interval", required_argument, NULL, 'i'},
        { "verbose", no_argument, NULL, 'v'},
        { "help", no_argument, NULL, 'h'},
        { NULL }
};

enum {
        F_SRC_DIR = 0,
        F_DEST_DIR
};

static int parse_port (const char *str, int dir, struct xnl_filter *filter);
static int parse_ip (const char *str, int dir, struct xnl_filter *filter);
static int parse_proto (const char *str, int dir, struct xnl_filter *filter);

static struct {
        const char *name;
        int (*handler) (const char *str, int dir, struct xnl_filter *filter);
        int arg;
} filter_table [] = {
        { "sport", parse_port, F_SRC_DIR },
        { "dport", parse_port, F_DEST_DIR },
        { "sip", parse_ip, F_SRC_DIR },
        { "dip", parse_ip, F_DEST_DIR },
        { "proto", parse_proto, 0 },
        { NULL }
};

static int parse_ip (const char *str, int dir, struct xnl_filter *filter)
{
        struct in_addr addr;
        int ret;

        if ((dir == F_SRC_DIR && filter->saddr != 0) ||
            (dir == F_DEST_DIR && filter->daddr != 0))
                return -1;

        if (strcmp(str, "any") == 0)
                return 0;

        ret = inet_pton(AF_INET, str, &addr);

        if (ret <= 0)
                return -1;

        if (dir == F_SRC_DIR) {
                memcpy(&filter->saddr, &addr, sizeof(addr));
        } else if (dir == F_DEST_DIR) {
                memcpy(&filter->daddr, &addr, sizeof(addr));
        }

        return 0;
}

static int parse_port (const char *str, int dir, struct xnl_filter *filter)
{
        char *end;
        intmax_t val;
        __u16 port;

        if ((dir == F_SRC_DIR && filter->sport != 0) ||
            (dir == F_DEST_DIR && filter->dport != 0))
                return -1;

        if (strcmp(str, "any") == 0)
                return 0;

        val = strtoimax(str, &end, 10);

        if (errno == ERANGE || val < 0 || val > UINT16_MAX || end == str || *end != '\0') {
                return -1;
        }

        port = htons(val);

        if (dir == F_SRC_DIR) {
                filter->sport = htons(port);
        } else if (dir == F_DEST_DIR) {
                filter->dport = htons(port);
        }

        return 0;
}

static int parse_proto (const char *str, int dir, struct xnl_filter *filter)
{
        (void) dir;

        dprint("parse_proto before: %d\n", filter->proto);

        if (filter->proto != 0)
                return -1;

        dprint("parse_proto: %s\n", str);

        if (strcmp(str, "any") == 0) {
                return 0;
        } else if (strcmp(str, "tcp") == 0) {
                filter->proto = XNL_FILTER_TCP;
                return 0;
        } else if (strcmp(str, "udp") == 0) {
                filter->proto = XNL_FILTER_UDP;
                return 0;
        }

        return -1;
}

static inline void ms2tv (unsigned long n, struct timeval *tv)
{
        tv->tv_sec = n / 1000;
        tv->tv_usec = (n % 1000) * 1000;
}

#define F_BUF_SIZ 128

const char *print_filter (struct xnl_filter *filter) {
        static char buf[128];
        char saddr[INET_ADDRSTRLEN];
        char daddr[INET_ADDRSTRLEN];
        char sport[6];
        char dport[6];
        char proto[4];

        (filter->saddr == 0) ? sprintf(saddr, "any") :
                inet_ntop(AF_INET, &filter->saddr, saddr, INET_ADDRSTRLEN);

        (filter->daddr == 0) ? sprintf(daddr, "any") :
                inet_ntop(AF_INET, &filter->daddr, daddr, INET_ADDRSTRLEN);

        (filter->sport == 0) ? sprintf(sport, "any") :
                sprintf(sport, "%d", filter->sport);

        (filter->dport == 0) ? sprintf(dport, "any") :
                sprintf(dport, "%d", filter->dport);

        if (filter->proto == XNL_FILTER_UDP) {
                sprintf(proto, "udp");
        } else if (filter->proto == XNL_FILTER_TCP) {
                sprintf(proto, "tcp");
        } else {
                sprintf(proto, "any");
        }

        snprintf(buf, 128, "%s %s:%s %s:%s",
                 proto, saddr, sport, daddr, dport);

        return buf;
}

int parse_filter(const char *str, struct xnl_filter *filter)
{
        char delim[] = " \t\r\n\v\f";
        char buf[F_BUF_SIZ];
        char *rule, *arg;
        struct xnl_filter f;

        memset(&f, 0, sizeof(f));

        if (strlen(str) > F_BUF_SIZ - 1) {
                fprintf(stderr, "Filter string is too long: %s\n", str);
                return -1;
        }

        snprintf(buf, F_BUF_SIZ, "%s", str);

        if ((rule = strtok(buf, delim)) == NULL)
                return -1;

        do {
                int i = 0;

                for (; filter_table[i].name != NULL; i++) {
                        dprint("str = %s, rule = %s\n", filter_table[i].name, rule);

                        if (strcmp(filter_table[i].name, rule) != 0)
                                continue;

                        arg = strtok(NULL, delim);

                        dprint("arg = %s\n", arg);

                        if (arg == NULL) {
                                fprintf(stderr, "Failed to parse filter (no arg): \"%s\"\n", str);
                                return -1;
                        }

                        if (filter_table[i].handler(arg, filter_table[i].arg, &f) < 0) {
                                fprintf(stderr, "Failed to parse filter (rule %s) \"%s\"\n", rule, str);
                                return -1;
                        }

                        break;
                }

                if (filter_table[i].name == NULL) {
                        fprintf(stderr, "Failed to parse filter, unknown token '%s'\n", rule);
                        break;
                }

                rule = strtok(NULL, delim);

        } while (rule != NULL);

        memcpy(filter, &f, sizeof(f));

        dprint("%s\n", print_filter(filter));

        return 0;
}


static void usage(int ret)
{
        const char *str =
                "Usage: %s [-S] [-N] [-p MSECS] INTERFACE FILTER_1 .. FILTER_N\n\n"
                "Options:\n"
                "  -S, --xdp-skb         Use XDP skb-mode\n"
                "  -N, --xdp-native      Enforce XDP native mode\n"
                "  -i, --interval=MSECS  Set the time interval to send data to ubus\n"
                "  -v, --verbose         Enable verbose mode\n"
                "  -h, --help            Print the usage and exit\n"
                "\n"
                "  INTERFACE             The network interace to listen on (e.g. tun0)\n"
                "  FILTER_1 .. FILTER_N  Set of filters for matching packets (each filter\n"
                "                        is specified as quoted string; number of filters\n"
                "                        must be between 1 and %d)\n"
                "\n";

        fprintf(stderr, str, PROG_NAME, XNL_MAX_FILTERS);
        exit(ret);
}

int main (int argc, char **argv)
{
        struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
        struct bpf_object *obj;
        int prog_fd, idx;
        char opt, *ch;
        unsigned long ms;
        __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
        int if_index;

        if (setrlimit(RLIMIT_MEMLOCK, &r)) {
                fprintf(stderr, "%s: setrlimit() failed: %s\n", PROG_NAME, strerror(errno));
                exit(EXIT_FAILURE);
        }

        while ((opt = getopt_long(argc, argv, opts, lopts, &idx)) != -1) {
                switch(opt) {
                case 'h':
                        usage(EXIT_SUCCESS);
                        break;
                case 'v':
                        verbose++;
                        break;
                case 'S':
                        xdp_flags &= ~XDP_FLAGS_MODES;
                        xdp_flags |= XDP_FLAGS_SKB_MODE;
                        break;
                case 'N':
                        xdp_flags &= ~XDP_FLAGS_MODES;
                        xdp_flags |= XDP_FLAGS_DRV_MODE;
                        break;
                case 'i':
                        ms = strtoul(optarg, &ch, 10);

                        if ((ch == optarg) || (*ch != '\0') || (ms == 0) || (ms == UINT_MAX)) {
                                fprintf(stderr, "%s: invalid interval\n", PROG_NAME);
                                exit(EXIT_FAILURE);


                        ms2tv(ms, &log_interval);

                        break;
                default:
                        usage(EXIT_FAILURE);
                        break;
                        }
                }
        }

        if (argc - optind < 2 || argc - optind > 1 + XNL_MAX_FILTERS)
                usage(EXIT_FAILURE);

        if_index = if_nametoindex(argv[optind]);

        if (if_index == 0) {
                fprintf(stderr, "%s: unknown interface '%s': %s\n", PROG_NAME,
                        argv[optind], strerror(errno));
                exit(EXIT_FAILURE);
        }

        optind++;

        while (optind < argc) {
                struct xnl_filter f;

                if (parse_filter(argv[optind], &f) < 0) {
                        fprintf(stderr, "%s: failed to parse filter '%s'\n", PROG_NAME, argv[optind]);
                        exit(EXIT_FAILURE);
                }

                optind++;
        }

        struct bpf_prog_load_attr prog_load_attr = {
                .prog_type      = BPF_PROG_TYPE_XDP,
                .file           = XDP_PROG_NAME,
        };

        if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
                exit(EXIT_FAILURE);


        uloop_init();


        uloop_done();
}