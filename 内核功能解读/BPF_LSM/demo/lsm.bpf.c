// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2020 Google LLC.
 */

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PASS 0
#define NOPASS 1

#define AF_INET 2 // 标记为 IPV4

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} event SEC(".maps");

struct info
{
    u64 gpid;
    u32 addr;
};

SEC("lsm/socket_connect")
int BPF_PROG(restrict_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    struct info *value;
    /* ret is the return value from the previous BPF program
     * or 0 if it's the first hook.
     */
    if (ret != 0)
        return ret;

    if (address->sa_family != AF_INET)
        return 0;

    struct sockaddr_in *addr = (struct sockaddr_in *)address;
    u32 dest = addr->sin_addr.s_addr;

    /*
        使用以下公式可以将IP地址转换为u32值：
            u32 = (A × 256^3) + (B × 256^2) + (C × 256) + D
    */
    const u32 blockme = 16843009; // 1.1.1.1
    if (dest == blockme)
        return -NOPASS;

    value = bpf_ringbuf_reserve(&event, sizeof(*value), 0);
    if (value == NULL)
        return -1;

    value->gpid = bpf_get_current_pid_tgid();
    value->addr = dest;

    bpf_ringbuf_submit(value, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";