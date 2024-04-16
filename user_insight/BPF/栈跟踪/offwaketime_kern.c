/* Copyright (c) 2016 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "offwaketime_kern.h"

#define MINBLOCK_US 1
#define STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
#define _(P)                                            \
    ({                                                  \
        typeof(P) val;                                  \
        bpf_probe_read_kernel(&val, sizeof(val), &(P)); \
        val;                                            \
    })

static inline int update_counts(void *ctx, u32 pid, u64 delta)
{
    struct wokeby_t *woke;
    u64 zero = 0, *val;
    struct key_t key;

    __builtin_memset(&key.waker, 0, sizeof(key.waker));
    bpf_get_current_comm(&key.target, sizeof(key.target));
    key.tret = bpf_get_stackid(ctx, &stackmap, STACKID_FLAGS);
    key.wret = 0;
    woke = bpf_map_lookup_elem(&wokeby, &pid);

    if (woke)
    {
        key.wret = woke->ret;
        __builtin_memcpy(&key.waker, woke->name, sizeof(key.waker));
        bpf_map_delete_elem(&wokeby, &pid);
    }

    val = bpf_map_lookup_elem(&counts, &key);
    if (!val)
    {
        bpf_map_update_elem(&counts, &key, &zero, BPF_NOEXIST);
        // 确保更新成功
        val = bpf_map_lookup_elem(&counts, &key);
        if (!val)
            return 0;
    }

    (*val) += delta;
    return 0;
}

/*
    try_to_wake_up 函数功能：
        唤醒一个被阻塞的进程，并将其放入可运行队列中等待 CPU 调度
*/
SEC("kprobe/try_to_wake_up")
int waker(struct pt_regs *ctx)
{
    struct task_struct *p = (struct task_struct *)PT_REGS_PARM1(ctx);
    struct wokeby_t woke;
    u32 pid;
    pid = _(p->pid);
    bpf_get_current_comm(&woke.name, sizeof(woke.name));
    woke.ret = bpf_get_stackid(ctx, &stackmap, STACKID_FLAGS);
    bpf_map_update_elem(&wokeby, &pid, &woke, BPF_ANY);
    return 0;
}

/*
    sched_switch 函数功能：
            记录调度器在不同进程之间进行切换时的详细信息，包括时间戳、CPU 编号、前后进程的 PID、状
            态信息以及函数调用栈信息
        参数解析：
            tchart: 指向时间图表结构的指针，用于记录不同事件的时间信息
            cpu：发生调度切换的 CPU 编号
            timestamp: 切换发生的时间戳
            prev_pid next_pid： 前一个进程和下一个进程的进程标识符（PID）
            prev_state: 进程的状态信息，运行状态、睡眠状态等...
            backtrace: 字符串指针，记录发生调度切换时的函数调用栈信息
            finish_task_switch 函数功能：
        在任务切换之后进行清理工作，包括解决锁定问题和处理特定于体系结构的操作，并确保栈和变量
        的正确性
        函数必须在上下文切换之后调用，与之前的prepare_task_switch 函数一起配对使用。它会解
        决由
    prepare_task_switch 设置的锁定，并执行其他特定于体系结构的清理操作。
        参数解析：
            prev: 前一个进程指针
*/
#if 1
SEC("tracepoint/sched/sched_switch")
int oncpu(struct sched_switch_args *ctx)
{
    /* record previous thread sleep time */
    u32 pid = ctx->prev_pid;
#else
SEC("kprobe/finish_task_switch")
int oncpu(struct pt_regs *ctx)
{
    struct task_struct *p = (void *)PT_REGS_PARM1(ctx);
    /* record previous thread sleep time */
    u32 pid = _(p->pid);
#endif
    u64 delta, ts, *tsp;
    // 获取当前时间
    ts = bpf_ktime_get_ns();
    // 此时的 pid 为上一个线程 PID
    bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);

    /* calculate current thread's delta time */
    // 此时的 pid 为当前线程 PID
    pid = bpf_get_current_pid_tgid();
    // 判断上个线程和当前线程是否为同一个
    tsp = bpf_map_lookup_elem(&start, &pid);
    if (!tsp)
        /* missed start or filtered */
        return 0;

    // 获取增量的信息
    delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start, &pid);
    delta = delta / 1000;

    if (delta < MINBLOCK_US)
        return 0;

    return update_counts(ctx, pid, delta);
}

char _license[] SEC("license") = "GPL";