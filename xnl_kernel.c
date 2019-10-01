/* SPDX-License-Identifier: GPL-2.0 or MIT */

#include <stdint.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <netinet/in.h>

#include "bpf_helpers.h"
#include "common.h"

#define DEBUG 1
#ifdef  DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)                                             \
                ({                                                      \
                        char ____fmt[] = fmt;                           \
                        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                                     ##__VA_ARGS__);                    \
                })
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif

struct bpf_map_def SEC("stats") xnl_rules = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(__u32),
        .value_size = sizeof(struct xnl_filters),
        .max_entries = 1,
};

struct bpf_map_def SEC("stats") xnl_counters = {
        .type = BPF_MAP_TYPE_PERCPU_ARRAY,
        .key_size = sizeof(__u32),
        .value_size = sizeof(struct xnl_filter),
        .max_entries = XNL_MAX_FILTERS,
};

SEC("xdp")
int xdp_pass (struct xdp_md *ctx)
{
        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;
        __u64 len;
        __u32 l3_offset;
        __u32 l4_offset;
        __u16 eth_proto;
        __u8 proto;
        __u8 iph_len;
        __u32 zero = 0;

        struct iphdr *iph;
        struct ethhdr *ehdr;
        struct xnl_filters *filters;

        len = data_end - data;
        ehdr = (struct ethhdr *)data;
        l3_offset = sizeof(*ehdr);

        if ((void *)ehdr + l3_offset > data_end) {
                bpf_debug("Failed to parse Ethernet header");
                return XDP_PASS; /* XDP_ABORTED? */
        }

        eth_proto = ntohs(ehdr->h_proto);

        /* Only need to listen to incoming IPv4 packets, ETH_P_IP does
         * the job  */
        if (eth_proto != ETH_P_IP)
                return XDP_PASS;

        iph = (struct iphdr *) (data + l3_offset);
        iph_len = iph->ihl;

        if (iph->protocol == IPPROTO_TCP) {
                proto = XNL_FILTER_TCP;
        } else if (iph->protocol == IPPROTO_UDP) {
                proto = XNL_FILTER_UDP;
        } else {
                /* Ignore everything but TCP and UDP packets */
                return XDP_PASS;
        }

        l4_offset = l3_offset + sizeof(*iph);

        filters = bpf_map_lookup_elem(&xnl_rules, &zero);

        if (!filters) {
                bpf_debug("bpf_map_lookup_elem(rules) failed");
                return XDP_PASS;
        }

        for (__u32 i = 0; i < filters->num; i++) {
                struct xnl_filter *filter = &(filters->filters[i]);

                if (proto != XNL_FILTER_ANY && proto != filter->proto)
                        continue;

                if (filter->saddr != 0 && iph->saddr != filter->saddr)
                        continue;

                if (filter->daddr != 0 && iph->daddr != filter->daddr)
                        continue;

                if (filter->sport != 0 || filter->dport != 0) {
                        if (iph->protocol == IPPROTO_TCP) {
                                struct tcphdr *hdr = data + l4_offset;

                                if (filter->sport && filter->sport != ntohs(hdr->source))
                                        continue;

                                if (filter->dport && filter->dport != ntohs(hdr->dest))
                                        continue;
                        } else if (iph->protocol == IPPROTO_UDP) {
                                struct udphdr *hdr = data + l4_offset;

                                if (filter->sport && filter->sport != ntohs(hdr->source))
                                        continue;

                                if (filter->dport && filter->dport != ntohs(hdr->dest))
                                        continue;
                        }
                }

                struct xnl_counters *counters = bpf_map_lookup_elem(&xnl_counters, &i);

                if (!counters) {
                        bpf_debug("bpf_map_lookup_elem(stats) failed");
                        continue;
                }

                counters->pkts++;
                counters->bytes += len;
        }

        return XDP_PASS;
}