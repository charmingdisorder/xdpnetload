#ifndef _XDPNETLOAD_COMMON_H_
#define _XDPNETLOAD_COMMON_H_

#include <linux/types.h>

#define XNL_MAX_FILTERS 5

enum {
        XNL_FILTER_UDP = 0,
        XNL_FILTER_TCP,
        XNL_FILTER_ANY
};

/* xnl_filter describes filtering rule */
struct xnl_filter {
        __u32 saddr;
        __u32 daddr;

        __u16 sport;
        __u16 dport;

        __u8 proto;
};

struct xnl_filters {
        __u64 started;      /* Time started */
        __u32 num;          /* Number of filtering rules */

        struct xnl_filter filters[XNL_MAX_FILTERS];
};

/*
 * xnl_counters accumulates statistics regarding network traffic
 * related to defined rules
 */
struct xnl_counters {
        __u64 pkts;
        __u64 bytes;
};

#endif