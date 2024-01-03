#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define PASS 0
#define NOPASS 1

SEC("lsm/inode_unlink")
int BPF_PROG(s_inode_unlink, struct inode *dir, struct dentry *dentry, int ret)
{
    if (ret != 0)
        return ret;

    u64 tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)tgid;

    const char fmt_str[] = "security inode unlink %lu";
    bpf_trace_printk(fmt_str, sizeof(fmt_str), tid);

    return PASS;
}

char LICENSE[] SEC("license") = "GPL";