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

#include <json-c/json.h>
#include <libubox/blobmsg_json.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>

#include <include/bpf_util.h>

#define PROG_NAME "xdpnetload"

#define DEBUG 1

#if defined(DEBUG) && DEBUG > 0
#define dprint(fmt, args...) fprintf(stderr, "[DEBUG] %s:%d:%s(): " fmt, \
                                      __FILE__, __LINE__, __func__, ##args)
#else
#define dprint(fmt, args...)
#endif

#define vprint(fmt, args...) if (verbose) fprintf(stderr, "[%s] %s(): " fmt, \
                                                  get_ts(), __func__, ##args)

static unsigned int verbose = 0;
static unsigned long report_interval = 1000; /* send statistics every N msecs */

static int if_index = -1;

static unsigned int nr_cpus;

static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
static __u32 prog_id;

static unsigned int num_filters = 0;
struct xnl_filter filters[XNL_MAX_FILTERS];

static int rules_map_fd;
static int counters_map_fd;

struct uloop_timeout bandwidth_timer;
struct uloop_timeout report_timer;

static struct ubus_context *ubus_ctx;
static struct blob_buf blob_buf;

//static struct xnl_stats stats[XNL_MAX_FILTERS];

static struct  {
        /* calc_bandwidth (per-sec timer) */
        __u64 sec_bytes;
        __u64 sec_min;
        __u64 sec_max;

        /* report_stats (user-specified timer) */
        __u64 bytes;
        __u64 pkts;
        __u64 min_bps;
        __u64 max_bps;

        unsigned long long started;
        unsigned long long reported;
} stats[XNL_MAX_FILTERS];


static const char *opts = "fSNvhi:s:";
static struct option lopts[] = {
        { "force" , no_argument, NULL, 'f'},
        { "socket", no_argument, NULL, 's'},
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

static const char *get_ts()
{
        static char buf[32];
        double stamp;
        struct timeval tv;

        gettimeofday(&tv, NULL);
        stamp = (double)tv.tv_sec + (double)((double)tv.tv_usec/1000000.0);
        snprintf(buf, BUFSIZ-1, "%f", stamp);

        return buf;
}

static int parse_ip(const char *str, int dir, struct xnl_filter *filter)
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

static int parse_port(const char *str, int dir, struct xnl_filter *filter)
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

static int parse_proto(const char *str, int dir, struct xnl_filter *filter)
{
        (void) dir;

        if (filter->proto != 0)
                return -1;

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

#if 0
static inline void ms2tv(unsigned long n, struct timeval *tv)
{
        tv->tv_sec = n / 1000;
        tv->tv_usec = (n % 1000) * 1000;
}
#endif

#define F_BUF_SIZ 128

const char *print_filter (struct xnl_filter *filter) {
        static char buf[128];
        char saddr[INET_ADDRSTRLEN];
        char daddr[INET_ADDRSTRLEN];
        char sport[6];
        char dport[6];
        char proto[4];

        (void)((filter->saddr == 0) ? (void)sprintf(saddr, "any") :
               (void)inet_ntop(AF_INET, &filter->saddr, saddr, INET_ADDRSTRLEN));

        (void)((filter->daddr == 0) ? (void)sprintf(daddr, "any") :
               (void)inet_ntop(AF_INET, &filter->daddr, daddr, INET_ADDRSTRLEN));

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
                        if (strcmp(filter_table[i].name, rule) != 0)
                                continue;

                        arg = strtok(NULL, delim);

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
                        return -1;
                }

                rule = strtok(NULL, delim);

        } while (rule != NULL);

        f.is_set = 1;

        memcpy(filter, &f, sizeof(f));

        vprint("New filter defined: %s\n", print_filter(filter));

        return 0;
}

void calc_bandwidth(struct uloop_timeout *t)
{
        (void)t;
        unsigned int i, j;
        struct xnl_counters counters [nr_cpus];
        void *arr;

        for (i=0; i<num_filters; i++) {
                __u64 bytes = 0;
                void *tbl;

                if (bpf_map_lookup_elem(counters_map_fd, &i, counters) != 0) {
                        fprintf(stderr, "%s: bpf_map_lookup_elem() failed\n", __func__);
                        uloop_end();
                        return;
                }

                for (j=0; j<nr_cpus; j++) {
                        bytes += counters[j].bytes;
                }

                __u64 diff = bytes - stats[i].sec_bytes;

                if (stats[i].sec_bytes == 0) {
                        stats[i].sec_max = diff;
                        stats[i].sec_min = diff;
                        stats[i].sec_bytes = bytes;

                        continue;
                }

                if (diff > stats[i].sec_max) {
                        stats[i].sec_max = diff;
                }

                if (diff < stats[i].sec_min) {
                        stats[i].sec_min = diff;
                }

                stats[i].sec_bytes = bytes;

                dprint("%s: filter %u: diff = %llu, min = %llu, max = %llu\n", __func__,
                       i, diff, stats[i].sec_min, stats[i].sec_max);
        }

        uloop_timeout_set(&bandwidth_timer, 1000);

        return;
}

static inline unsigned long long monotime(void) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return (ts.tv_sec * 1000000LL + ts.tv_nsec / 1000);
}

static void report_stats(struct uloop_timeout *t)
{
        (void) t;
        unsigned int i, j;
        unsigned long long now;
        int to_send = 0;

        struct xnl_counters counters [nr_cpus];

        blob_buf_init(&blob_buf, 0);

        for (i=0; i<num_filters; i++) {
                __u64 bytes = 0;
                __u64 pkts = 0;
                __u64 total_bps = 0;
                __u64 cur_bps = 0;

                if (bpf_map_lookup_elem(counters_map_fd, &i, counters) != 0) {
                        fprintf(stderr, "%s: bpf_map_lookup_elem() failed\n", __func__);
                        uloop_end();
                        return;
                }

                for (j=0; j<nr_cpus; j++) {
                        bytes += counters[j].bytes;
                        pkts += counters[j].pkts;
                }

                now = monotime();

                if (stats[i].started) {
                        void *tbl;

                        /* mbit/sec * microsec = bits => mbit/sec = bits/microces */

                        total_bps = (bytes*8*1000000UL)/(now - stats[i].started);
                        cur_bps = ((bytes - stats[i].bytes)*8*1000000UL)/(now - stats[i].reported);

                        if (cur_bps < stats[i].min_bps) {
                                stats[i].min_bps = cur_bps;
                        }

                        if (cur_bps > stats[i].max_bps) {
                                stats[i].max_bps = cur_bps;
                        }

                        if (!stats[i].started) {
                                stats[i].started = stats[i].reported = now;
                        }

                        stats[i].bytes = bytes;
                        stats[i].pkts = pkts;
                        stats[i].reported = now;

                        dprint("filter %u: bytes=%llu, cur_bps = %llu, total_mbps=%.5f, cur_mbps=%.5f\n",
                               i, bytes, cur_bps, (double)total_bps / 1000000.0, (double)cur_bps / 1000000.0);


                        tbl = blobmsg_open_table(&blob_buf, NULL);
                        blobmsg_add_u32(&blob_buf, "id", i);
                        blobmsg_add_u64(&blob_buf, "bytes", bytes);
                        blobmsg_add_u64(&blob_buf, "pkts", pkts);
                        blobmsg_add_double(&blob_buf, "total_mbps", (double)total_bps / 1000000.0);
                        blobmsg_add_double(&blob_buf, "current_mbps", (double)cur_bps / 1000000.0);
                        blobmsg_add_double(&blob_buf, "min_mbps", (double)stats[i].min_bps / 1000000.0);
                        blobmsg_add_double(&blob_buf, "max_mbps", (double)stats[i].max_bps / 1000000.0);
                        blobmsg_close_table(&blob_buf, tbl);

                        to_send = 1;
                } else {
                        stats[i].started = stats[i].reported = now;
                        stats[i].bytes = bytes;
                        stats[i].pkts = pkts;
                        stats[i].max_bps = 0;
                        stats[i].min_bps = UINT64_MAX;
                }
        }

        if (to_send)
                ubus_send_event(ubus_ctx, "xdpnetload", blob_buf.head);

        uloop_timeout_set(&report_timer, report_interval);

        return;
}


static void usage(int ret)
{
        const char *str =
                "Usage: %s [OPTION]... INTERFACE FILTER_1 .. FILTER_N\n\n"
                "Options:\n"
                "  -f  --force           Force loading mode\n"
                "  -S, --xdp-skb         Use XDP skb-mode\n"
                "  -N, --xdp-native      Use XDP native mode\n"
                "  -i, --interval=MSECS  Set the time interval to send data to ubus\n"
                "  -s, --socket=PATH     Set the UNIX domain socket to connect to ubus\n"
                "  -v, --verbose         Enable verbose mode\n"
                "  -h, --help            Print the usage and exit\n"
                "\n"
                "  INTERFACE             The network interace to listen on (e.g. tun0)\n"
                "  FILTER_1 .. FILTER_N  Set of filters for matching packets (each filter\n"
                "                        is specified as quoted string; number of filters\n"
                "                        must be between 1 and %d)\n"
                "\n"
                "Filter syntax:\n"
                "  line = ( rule )\n"
                "  rule = ( \"sip\" ip | \"dip\" ip | \"sport\" port | \"dport\" port |\n"
                "           \"proto\" proto )\n"
                "  proto = \"udp\" | \"tcp\" | \"any\"\n"
                "  ip = ipaddr | \"any\"\n"
                "  port = portnum | \"any\"\n"
                "\n"
                ;

        fprintf(stderr, str, PROG_NAME, XNL_MAX_FILTERS);
        exit(ret);
}

static void sig_handler(int sig)
{
        (void)sig;
        __u32 cur_prog_id = 0;

        if (bpf_get_link_xdp_id(if_index, &cur_prog_id, xdp_flags)) {
                fprintf(stderr, "%s: bpf_get_link_xdp_fd() failed\n", PROG_NAME);
                uloop_end();
                return;
        }

        vprint("Cleaning up\n");

        if (!cur_prog_id) {
                fprintf(stderr, "%s: bpf_get_link_xdp_fd() failed to get prog id\n",
                        PROG_NAME);
                uloop_end();
                return;
        }

        if (prog_id == cur_prog_id) {
                bpf_set_link_xdp_fd(if_index, -1, xdp_flags);
                vprint("Removed XDP program\n");
        } else {
                fprintf(stderr, "%s: xdp program was modified on interface\n",
                        PROG_NAME);
        }

        uloop_end();
        return;
}

int main(int argc, char **argv)
{
        struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
        struct bpf_object *obj;
        struct bpf_prog_info info = {};
        __u32 info_len;
        char opt;
        int prog_fd;
        const char *ubus_socket = NULL;

        if (setrlimit(RLIMIT_MEMLOCK, &r)) {
                fprintf(stderr, "%s: setrlimit() failed: %s\n", PROG_NAME, strerror(errno));
                exit(EXIT_FAILURE);
        }

        char *ch;

        while ((opt = getopt_long(argc, argv, opts, lopts, NULL)) != -1) {
                switch(opt) {
                case 'h':
                        usage(EXIT_SUCCESS);
                        break;
                case 'v':
                        verbose++;
                        break;
                case 's':
                        ubus_socket = optarg;
                        break;
                case 'f':
                        xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
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
                        report_interval = strtoul(optarg, &ch, 10);

                        if ((ch == optarg) || (*ch != '\0') || (report_interval == 0) ||
                            (report_interval == UINT_MAX)) {
                                fprintf(stderr, "%s: invalid interval\n", PROG_NAME);
                                exit(EXIT_FAILURE);
                        }

                        dprint("stat interval = %lu\n", report_interval);

                        break;
                default:
                        usage(EXIT_FAILURE);
                        break;
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

        num_filters = argc - optind;
        unsigned int i = 0;

        while (optind < argc) {
                if (parse_filter(argv[optind], &filters[i]) < 0) {
                        fprintf(stderr, "%s: failed to parse filter '%s'\n", PROG_NAME, argv[optind]);
                        exit(EXIT_FAILURE);
                }

                i++;
                optind++;
        }

        ubus_ctx = ubus_connect(ubus_socket);

         if (!ubus_ctx) {
                fprintf(stderr, "%s: failed to connect to ubus\n", PROG_NAME);
                exit(EXIT_FAILURE);
        }

        nr_cpus = bpf_num_possible_cpus();

        struct bpf_prog_load_attr prog_load_attr = {
                .prog_type      = BPF_PROG_TYPE_XDP,
                .file           = XDP_PROG_NAME,
        };

        if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
                exit(EXIT_FAILURE);

        rules_map_fd = bpf_object__find_map_fd_by_name(obj, "xnl_rules");
        counters_map_fd = bpf_object__find_map_fd_by_name(obj, "xnl_counters");

        if (rules_map_fd < 0 || counters_map_fd < 0) {
                fprintf(stderr, "%s: bpf_object__find_map_fd_by_name() failed\n", PROG_NAME);
                exit(EXIT_FAILURE);
        }

        if (bpf_set_link_xdp_fd(if_index, prog_fd, xdp_flags) < 0) {
                fprintf(stderr, "%s: bpf_set_link_xdp_fd() failed\n", PROG_NAME);
                exit(EXIT_FAILURE);
        }

        info_len = sizeof(info);
        if (bpf_obj_get_info_by_fd(prog_fd, &info, &info_len)) {
                fprintf(stderr, "%s: bpf_obj_get_info_by_fd() failed\n", PROG_NAME);
                goto err;
        }

        prog_id = info.id;

        for (i=0; i<num_filters; i++) {
                if (bpf_map_update_elem(rules_map_fd, &i, &filters[i], BPF_ANY)) {
                        fprintf(stderr, "%s: bpf_map_update_elem(rules_map_fd) failed\n",
                                PROG_NAME);
                        goto err;
                }
        }

        signal(SIGINT, sig_handler);
        signal(SIGTERM, sig_handler);

        bandwidth_timer.cb = calc_bandwidth;
        report_timer.cb = report_stats;

        vprint("Entering mainloop\n");

        uloop_init();
#if 0
        uloop_timeout_set(&bandwidth_timer, 1000);
#endif
        uloop_timeout_set(&report_timer, report_interval);

        uloop_run();

        uloop_done();

        exit(EXIT_SUCCESS);
err:
        sig_handler(0);
        exit(EXIT_FAILURE);
}