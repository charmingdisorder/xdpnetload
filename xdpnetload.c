// SPDX-License-Identifier: GPL-2.0 or MIT

#include "common.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <sys/time.h>
#include <sys/resource.h>

#include <libubus.h>

#define PROG_NAME "xdpnetload"

static void usage(const char *prog)
{
        const char *str =
                "  Usage: %s [-S] [-N] INTERFACE NUM RULES\n"
                "  Options:\n"
                "  -S, --xdp-skb=n	Use XDP skb-mode\n"
                "  -N, --xdp-native=n	Enforce XDP native mode\n"
                "  INTERFACE      The network interace to listen on (e.g. eth0, tun0)\n"
                "  NUM            Number of user-specified filtering rules\n"
                "  RULE_X	  \n"
                "\n";
        fprintf(stderr, str, prog);
        exit(EXIT_FAILURE);
}

int main (int argc, char **argv)
{
        struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
        struct bpf_object *obj;
        int prog_fd;

        struct bpf_prog_load_attr prog_load_attr = {
                .prog_type      = BPF_PROG_TYPE_XDP,
                .file           = "xnl_kernel.o",
        };

        uloop_init();

        if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
                return 1;

}