### ebpf prog bpf_get_stackid 解析
```c
/*
    ebpf helper （编号为 27）函数 bpf_get_stackid 功能：
    用于遍历用户或内核栈并返回其 ID，该ID和stack信息关联，ID是对当前栈的指令指针地址进行
    32-bit hash 得到
    参数说明：
    void *ctx: 当前执行上下文的指针 ctx
    void *map: 指向类型为 BPF_MAP_TYPE_STACK_TRACE 的 map
    __u64 flags: 低 8 位表示需要跳过的栈帧数（0 - 255），高位标志位如下
    BPF_F_USER_STACK：收集用户空间栈而不是内核栈。
    BPF_F_FAST_STACK_CMP：只比较栈的哈希值。（性能高，存在哈希冲突）
    BPF_F_REUSE_STACKID：如果哈希到同一 stackid 的两个不同栈，则丢弃旧的栈。
    返回值：
    32 位的栈 ID，在需要生成火焰图或 off-cpu 图等图形时，可将其与其他数据（包括其他栈
    ID）
    组合起来，并用作映射的键。
    与使用展开循环的 bpf_probe_read() 相比，bpf_get_stackid() 可以采集最多
    PERF_MAX_STACK_DEPTH（默认值为 127）
    个内核和用户栈帧，效率更高。但需要注意的是，该函数受到操作系统中 sysctl 配置项
    kernel.perf_event_max_stack
    的限制，如果需要分析大型用户栈（如 Java 程序的栈），则需要手动增加该配置项的值
*/
static long (*bpf_get_stackid)(void *ctx, void *map, __u64 flags) = (void *) 27
```

### ebpf map BPF_MAP_TYPE_STACK_TRACE 解析
```c
/*
    ebpf map 类型，用于栈跟踪
        struct
        {
            __uint(type, BPF_MAP_TYPE_STACK_TRACE);
            __uint(key_size, sizeof(u32));
            __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
            __uint(max_entries, 10000);
        } stackmap SEC(".maps");
    key：stack ID 为 bpf_get_stackid 函数调用的返回值
    value_size: 保存符号名对应的符号地址
*/
```