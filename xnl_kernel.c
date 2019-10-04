/* SPDX-License-Identifier: GPL-2.0 or MIT */

#include <stdint.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <netinet/in.h>

#include "bpf_helpers.h"
#include <linux/bpf.h>
#include "common.h"

char _license[] SEC("license") = "Dual MIT/GPL";

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

struct bpf_map_def SEC("maps") xnl_rules = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(__u32),
//        .value_size = sizeof(struct xnl_filters),
//        .max_entries = 1,
        .value_size = sizeof(struct xnl_filter),
        .max_entries = XNL_MAX_FILTERS,

};

struct bpf_map_def SEC("maps") xnl_counters = {
        .type = BPF_MAP_TYPE_PERCPU_ARRAY,
        .key_size = sizeof(__u32),
        .value_size = sizeof(struct xnl_counters),
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

        struct iphdr *iph;
        struct ethhdr *ehdr;

        len = data_end - data;
        ehdr = (struct ethhdr *)data;
        l3_offset = sizeof(*ehdr);

        if ((void *)ehdr + sizeof(*ehdr) + l3_offset > data_end) {
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

        __u32 saddr = iph->saddr;
        __u32 daddr = iph->daddr;
        __u16 sport = 0;
        __u16 dport = 0;

        l4_offset = l3_offset + sizeof(*iph);

        if (data + l4_offset > data_end) {
                bpf_debug("l4_offset > data_end");
                return XDP_PASS; /* XXX */
        }

        if (proto == XNL_FILTER_TCP) {
                struct tcphdr *hdr = data + l4_offset;

                if ((void *)hdr + sizeof(*hdr) > data_end) {
                        bpf_debug("l4_offset check");
                        return XDP_PASS;
                }

                /*
                sport = ntohs(hdr->source);
                dport = ntohs(hdr->dest);
                */

                sport = hdr->source;
                dport = hdr->dest;
        } else {
                /* UDP */
                struct udphdr *hdr = data + l4_offset;

                if ((void *)hdr + sizeof(*hdr) > data_end) {
                        bpf_debug("l4_offset check");
                        return XDP_PASS;
                }

                /*
                sport = ntohs(hdr->source);
                dport = ntohs(hdr->dest);
                */

                sport = ntohs(hdr->source);
                dport = ntohs(hdr->dest);

        }

#pragma clang loop unroll(full)
        for (__u8 i = 0; i < XNL_MAX_FILTERS; i++) {
                __u32 j = i; /* to unroll */

                struct xnl_filter *filter = bpf_map_lookup_elem(&xnl_rules, &j);

                if (!filter) {
                        bpf_debug("bpf_map_lookup_elem(xnl_rules)");
                        return XDP_PASS;
                }

                if (filter->is_set == 0) break;

                if (proto != XNL_FILTER_ANY && proto != filter->proto)
                        continue;

                if (filter->saddr != 0 && saddr != filter->saddr)
                        continue;

                if (filter->daddr != 0 && daddr != filter->daddr)
                        continue;

                if (filter->sport != 0 && sport != filter->sport)
                        continue;

                if (filter->dport != 0 && dport != filter->dport)
                        continue;

                struct xnl_counters *counters = bpf_map_lookup_elem(&xnl_counters, &j);

                if (!counters) {
                        bpf_debug("bpf_map_lookup_elem(xnl_counters)");
                        return XDP_PASS;
                }

                counters->pkts++;
                counters->bytes += len;
        }

        return XDP_PASS;
}