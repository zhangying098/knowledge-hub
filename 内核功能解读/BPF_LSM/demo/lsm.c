// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2020 Google LLC.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <argp.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/sysmacros.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <asm/types.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <arpa/inet.h>

#include <bpf/bpf.h>
#include <linux/bpf.h>

#include "lsm.skel.h"
bool running = true;

struct lsm_bpf *skel;
static void *mapfd;

struct info
{
    unsigned long long gpid;
    uint32_t addr;
};

static void memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
    {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
}

void u32_to_ip_str(uint32_t ip_int, char *ip_str)
{
    struct in_addr addr;
    addr.s_addr = htonl(ip_int);
    inet_ntop(AF_INET, &(addr.s_addr), ip_str, INET_ADDRSTRLEN);
}

static int lsm_monitor(void *ctx, void *data, size_t data_sz)
{
    int ret = 0;
    struct info *value = data;

    uint32_t ip_int = value->addr;
    char ip_str[INET_ADDRSTRLEN];
    u32_to_ip_str(ip_int, ip_str);

    printf("socket-connect info: IP - %llu, ADDR - %s\n", value->gpid, ip_str);
    return ret;
}

static void sig_handler()
{
    running = false;
}

static int do_monitor()
{
    int ret = 0;

    while (running)
    {
        ret = ring_buffer__poll(mapfd, 10000); /* timeout 100ms*/
        if (ret < 0)
        {
            printf("Error polling oom ring buffer:%d\n", ret);
            return ret;
        }
    }
    return 0;
}

static int load_sekl()
{
    int ret;
    skel = lsm_bpf__open_and_load();
    if (!skel)
    {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return -1;
    }

    ret = lsm_bpf__attach(skel);
    if (ret)
    {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        return -1;
    }

    mapfd = ring_buffer__new(bpf_map__fd(skel->maps.event), lsm_monitor, NULL, NULL);
    if (libbpf_get_error(mapfd))
    {
        fprintf(stderr, "Failed to create oom buffer\n");
        return -1;
    }
    return 0;
}

int main()
{
    int ret;
    struct bpf_object *obj;

    memlock_rlimit();
    ret = load_sekl();
    if (ret < 0)
        goto cleanup;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    ret = do_monitor();
cleanup:
    ring_buffer__free(mapfd);
    lsm_bpf__destroy(skel);
    return 0;
}