// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2016 Facebook
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <linux/perf_event.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "trace_helpers.h"
#define PRINT_RAW_ADDR 0

/* counts, stackmap */
static int map_fd[2];

// 查询地址 addr 对应的符号名，并打印
static void print_ksym(__u64 addr)
{
    struct ksym *sym;
    if (!addr)
        return;
    // 根据地址查询符号名
    sym = ksym_search(addr);
    if (!sym)
    {
        printf("ksym not found. Is kallsyms loaded?\n");
        return;
    }
    // 打印符号名
    if (PRINT_RAW_ADDR)
        printf("%s/%llx;\n", sym->name, addr);
    else
        printf("%s;\n", sym->name);
}

#define TASK_COMM_LEN 16
struct key_t
{
    // 保存执行到 kernel try_to_wake_up hook 点命令
    char waker[TASK_COMM_LEN];
    // 保存执行到 kernel sched_switch hook 点的命令
    char target[TASK_COMM_LEN];
    // 保存 kernel try_to_wake_up stackid 信息
    __u32 wret;
    // 保存 kernel sched_switch stackid 信息
    __u32 tret;
};

static void print_stack(struct key_t *key, __u64 count)
{
    __u64 ip[PERF_MAX_STACK_DEPTH] = {};
    static bool warned;
    int i;
    printf("%s;", key->target);
    /*
        根据 stack id 在 BPF_MAP_TYPE_STACK_TRACE 获取栈帧数据
        bpf_map_lookup_elem 返回值：
            0：成功获取数据
            非0：获取失败
    */
    if (bpf_map_lookup_elem(map_fd[1], &key->tret, ip) != 0)
    {
        printf("\n---;\n");
    }
    else
    {
        /*
            打印调用栈信息：
                栈信息以符号地址信息保存在 ip[] 数组中
                通过符号地址在符号表 /proc/kallsyms 检索符号名
        */
        for (i = PERF_MAX_STACK_DEPTH - 1; i >= 0; i--)
            print_ksym(ip[i]);
    }

    printf("\n-;\n");
    if (bpf_map_lookup_elem(map_fd[1], &key->wret, ip) != 0)
    {
        printf("\n---;\n");
    }
    else
    {
        for (i = 0; i < PERF_MAX_STACK_DEPTH; i++)
            print_ksym(ip[i]);
    }

    printf(";%s %lld\n", key->waker, count);
    if ((key->tret == -EEXIST || key->wret == -EEXIST) && !warned)
    {
        printf("stackmap collisions seen. Consider increasing size\n");
        warned = true;
    }
    else if (((int)(key->tret) < 0 || (int)(key->wret) < 0))
    {
        printf("err stackid %d %d\n", key->tret, key->wret);
    }
}

static void print_stacks(int fd)
{
    struct key_t key = {}, next_key;
    __u64 value;
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0)
    {
        bpf_map_lookup_elem(fd, &next_key, &value);
        print_stack(&next_key, value);
        key = next_key;
    }
}

static void int_exit(int sig)
{
    print_stacks(map_fd[0]);
    exit(0);
}

#include "trace_helpers.c"
int main(int argc, char **argv)
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    struct bpf_object *obj = NULL;
    struct bpf_link *links[2];
    struct bpf_program *prog;
    int delay = 1, i = 0;
    char filename[256];
    /*
        setrlimit 函数说明
        功能：
            通过 setrlimit 函数设置进程的资源限制
            参数说明：
        第一个参数
            RLIMIT_CORE：核心文件大小限制
            RLIMIT_CPU：CPU 时间限制
            RLIMIT_DATA：数据段大小限制
            RLIMIT_FSIZE：文件大小限制
            RLIMIT_NOFILE：最大打开文件描述符数限制
            RLIMIT_STACK：栈大小限制
            RLIMIT_AS：进程地址空间大小限制
            RLIMIT_LOCKS：文件锁数量限制
            RLIMIT_MEMLOCK：内存锁定大小限制
        第二个参数
            指向 rlimit 结构体指针，用于设置该资源的软限制和硬限制
            通过设置 r.rlim_cur 和 r.rlim_max 分别设置资源的软硬限制
            软限制是资源的当前可用限制，硬限制是资源的最大限制，超过硬限制将会导致进程被终
            止
    */
    if (setrlimit(RLIMIT_MEMLOCK, &r))
    {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return 1;
    }

    // 加载内核符号表信息
    if (load_kallsyms())
    {
        printf("failed to process /proc/kallsyms\n");
        return 2;
    }

    snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
    obj = bpf_object__open_file(filename, NULL);

    if (libbpf_get_error(obj))
    {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        obj = NULL;
        goto cleanup;
    }

    /* load BPF program */
    if (bpf_object__load(obj))
    {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        goto cleanup;
    }

    map_fd[0] = bpf_object__find_map_fd_by_name(obj, "counts");
    map_fd[1] = bpf_object__find_map_fd_by_name(obj, "stackmap");

    if (map_fd[0] < 0 || map_fd[1] < 0)
    {
        fprintf(stderr, "ERROR: finding a map in obj file failed\n");
        goto cleanup;
    }

    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);

    bpf_object__for_each_program(prog, obj)
    {
        links[i] = bpf_program__attach(prog);
        if (libbpf_get_error(links[i]))
        {
            fprintf(stderr, "ERROR: bpf_program__attach failed\n");
            links[i] = NULL;
            goto cleanup;
        }
        i++;
    }

    if (argc > 1)
        delay = atoi(argv[1]);
    sleep(delay);
    print_stacks(map_fd[0]);

cleanup:
    for (i--; i >= 0; i--)
        bpf_link__destroy(links[i]);
    bpf_object__close(obj);
    return 0;
}
