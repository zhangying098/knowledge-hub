#ifndef __NTRACE_H__
#define __NTRACE_H__
#define TASK_COMM_LEN 16
#define PERF_MAX_STACK_DEPTH 127
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct key_t);
    __type(value, u64);
    __uint(max_entries, 10000);
} counts SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 10000);
} start SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct wokeby_t);
    __uint(max_entries, 10000);
} wokeby SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
    __uint(max_entries, 10000);
} stackmap SEC(".maps");

/* taken from /sys/kernel/debug/tracing/events/sched/sched_switch/format */
struct sched_switch_args
{
    unsigned long long pad;
    char prev_comm[16];
    int prev_pid;
    int prev_prio;
    long long prev_state;
    char next_comm[16];
    int next_pid;
    int next_prio;
};

struct key_t
{
    // 保存执行到 try_to_wake_up hook 点命令
    char waker[TASK_COMM_LEN];
    // 保存执行到 sched_switch hook 点的命令
    char target[TASK_COMM_LEN];
    // 保存 try_to_wake_up stackid 信息
    u32 wret;
    // 保存 sched_switch stackid 信息
    u32 tret;
};

struct wokeby_t
{
    // 触发当前 hook 的命令行
    char name[TASK_COMM_LEN];
    // 执行 bpf_get_stackid 返回的栈 ID
    u32 ret;
};
#endif