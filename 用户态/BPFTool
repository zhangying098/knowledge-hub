## `BPFTool `工具

### 一、简介

`BPFTool` 是一个用于检查`BPF`程序和映射的内核工具。`BPFTool` 在当前 `Linux` 发行版中默认是不被安装的。

### 二、特征查看

如果不知道内核哪个版本引入了那些类型程序，或`BPF`的`JIT`编译器是否开启，可以通过`BPFTool` 查看系统可访问的`BPF`特征。

```shell
# bpftool feature
Scanning system configuration...
bpf() syscall restricted to privileged users (admin can change)
JIT compiler is enabled
... ...
Scanning eBPF program types...                                                                       eBPF program_type socket_filter is available
eBPF program_type kprobe is available
... ...
Scanning eBPF map types...                                                                           eBPF map_type hash is available
eBPF map_type array is available
... ...
```

从以上输出中，可以看出系统限制特权用户执行 `bpf` 系统调用。同时，可以看出 `JIT` 已开启。较新版本的内核默认开启 `JIT` ，对于编译 `BPF` 程序有很大帮助。如果系统未开启 `JIT`，则可以通过运行下面命令开启它。

```shell
# echo 1 > /proc/sys/net/core/bpf_jit_enable
```

在特征输出中，还显示了系统中启用的程序类型和映射类型。输出的信息比这里显示的要更多，如程序类型支持的`BPF`帮助函数以及许多其他配置命令。

### 四、检查 `BPF`程序

`BPFTool` 可以提供内核中与`BPF`程序相关的直接信息。通过`BPFTool`，我们可以查看系统中已经运行的 `BPF` 程序信息。同时，该工具还可以加载并持久化以前从命令行编译的新`BPF`程序。

通过运行 `bpftool prog show` 检查系统中运行`BPF`程序的情况。如果系统使用 `systemd`作为系统初始化程序，则系统中可能已经加载了一些`BPF`程序，并将其附加到某些`cgroup`上。

```shell
# bpftool prog show
41: cgroup_device  tag 03b4eaae2f14641a  gpl
        loaded_at 2024-01-18T05:46:54+0800  uid 0
        xlated 296B  jited 163B  memlock 4096B  map_ids 3
55: tracepoint  name execve_entry  tag 7deea60e99ed3d12  gpl run_time_ns 2648942 run_cnt 730
        loaded_at 2024-01-18T06:32:33+0800  uid 0
        xlated 504B  jited 331B  memlock 4096B  map_ids 5
        btf_id 104
```

冒号左侧数字为**程序标识符**，后面将根据程序标识符检查程序的详细信息。从输出中，我们还可以了解到系统正在运行哪些类型的`BPF`程序。这里，系统运行两个`BPF`程序，被附加到`tracepoint` 内核函数 和 `cgroup` 套接字缓冲区中。如果这些程序是由 `Systemd` 启动的，那么程序的加载时间将与系统启动时的时间是匹配的。同时，还可以查看这些程序当前正在使用的内存大小，以及相关联的映射标识符。

通过运行 `bpftool prog show id 55`，`BPFTool`将仅显示程序标识符为 55 的相关信息。该命令支持 `--json`标志用来生成 `JSON`输出。我们可以方便地使用`jq` 之类的工具操作`JSON`输出，提供更结构化的输出。

```shell
# bpftool prog show id 55 --json | jq
{
  "id": 55,
  "type": "tracepoint",
  "name": "execve_entry",
  "tag": "7deea60e99ed3d12",
  "gpl_compatible": true,
  "run_time_ns": 2756103,
  "run_cnt": 749,
  "loaded_at": 1705530753,
  "uid": 0,
  "bytes_xlated": 504,
  "jited": true,
  "bytes_jited": 331,
  "bytes_memlock": 4096,
  "map_ids": [
    5
  ],
  "btf_id": 104
}
```

更高级的操作，过滤出`BPF`程序标识符、程序类型及程序何时被加载到内核中：

```shell
# bpftool prog show --json id 55 | jq -c '[.id, .type, .loaded_at]'
[55,"tracepoint",1705530753]
```

知道程序标识符后，可以使用 `BPFTool` 获取整个程序的数据。当你需要调试由编译器生成的`BPF`字节码时，这会很方便。

```shell
# bpftool prog dump xlated id 55
int execve_entry(struct trace_event_raw_sys_enter * ctx):
; const char *const *argv = (const char *const *)ctx->args[1];
   0: (79) r6 = *(u64 *)(r1 +24)
; const char *filename = (const char *)ctx->args[0];
   1: (79) r7 = *(u64 *)(r1 +16)
   2: (b7) r8 = 0
; struct entry en = {};
 ... ...
; return probe_entry(filename, argv);
  61: (b7) r0 = 0
  62: (95) exit
```

如果想得到这个程序更直观的表示（包括指令跳转），可以在命令中使用`visual`关键字，用于产出特定格式输出。可以使用诸如 `dotty`之类的工具，或其他可以绘制图形的程序，将输出转为图形表示：

```shell
# bpftool prog dump xlated id 2 visual &> output.out
# dot -Tpng output.out -o visual-graph.png
```

<img src="D:\副业\AI生图\图片\2024-01-18_071838.jpg" alt="2024-01-18_071838" style="zoom:50%;" />

在 5.1 版本或更高版本内核，还可以访问到程序运行时的统计信息。统计信息能告诉我们内核在`BPF`程序上花费的时长。默认情况下，系统中可能并未启用此功能。为了让内核记录相关数据，可以运行以下命令：

```shell
# sysctl -w kernel.bpf_stats_enabled=1
```

启用统计信息后，再次运行`BPFTool`时，将获得另外两条信息：内核花费在运行该程序上的总时间（`run_time_ns`），以及运行该程序的次数（`run_cnt`）:

```shell
55: tracepoint  name execve_entry  tag 7deea60e99ed3d12  gpl run_time_ns 2648942 run_cnt 730
        loaded_at 2024-01-18T06:32:33+0800  uid 0
        xlated 504B  jited 331B  memlock 4096B  map_ids 5
        btf_id 104
```

`BPFTool`不仅允许你检查程序的运行情况，还允许将新程序加载到内核中，并将它们附加到套接字和`cgroup`。例如，可以使用以下命令加载程序并将其持久化到`BPF`文件系统：

```shell
# mount bpffs -t bpf /sys/fs/bpf
# bpftool prog load bpf_prog.o /sys/fs/bpf/bpf_prog
```

由于该程序已持久化到文件系统，因此在运行后程序不会终止，可以使用`show`命令查看程序依然被加载。

### 五、检查`BPF`映射

`BPFTool` 还可以访问程序正在使用的`BPF`映射。使用 `BPFTool`的`map`参数显示映射信息：

```shell
# bpftool map show
2: prog_array  name hid_jmp_table  flags 0x0
        key 4B  value 4B  max_entries 1024  memlock 8512B
        owner_prog_type tracing  owner jited
3: hash  flags 0x0
        key 9B  value 1B  max_entries 500  memlock 59360B
```

这些映射可以使用程序`ID`过滤。

我们还可以使用 `BPFTool`创建和更新映射，列出映射中的所有元素。创建新映射需要提供的信息，与程序初始化映射需要提供的信息相同。我们要指定要创建哪种类型的映射、键和值的大小及映射名。因为不在程序初始化时初始化映射，所以需要将映射持久化到`BPF`文件系统中，以便稍后使用：

```shell
# bpftool map create /sys/fs/bpf/counter type array key 4 value 4 entries 5 name counter
# bpftool map show
2: prog_array  name hid_jmp_table  flags 0x0
        key 4B  value 4B  max_entries 1024  memlock 8512B
        owner_prog_type tracing  owner jited
... ...
6: array  name counter  flags 0x0
        key 4B  value 4B  max_entries 5  memlock 360B
```

像操作 `BPF`程序那样，当创建映射后，可以对映射的元素进行更新和删除。
**注意：不能从固定大小的数组中删除元素，只能更新它们。但可以从其他类型的映射中删除元素，如哈希映射。**



使用 `map update` 可以将新元素添加到映射中或者更新现有元素。我们可以使用上一个示例中获取的映射标识符执行下面命令。

```shell
# bpftool map update id 6 key 1 0 0 0 value 1 0 0 0
```

如果使用无效的键或值更新元素，`BPFTool`将返回错误：

```shell
# bpftool map update id 6 key 1 0 0 0 value 1 0 0
Error: value expected 4 bytes got 3
```

查看映射中元素的值，使用 `BPFTool`的`dump` 命令导出映射中所有元素的信息。当创建固定大小的数组映射时，可以看到`BPF`将所有元素初始化为空值：

```shell
# bpftool map dump id 6
key: 00 00 00 00  value: 00 00 00 00
key: 01 00 00 00  value: 01 00 00 00
key: 02 00 00 00  value: 00 00 00 00
key: 03 00 00 00  value: 00 00 00 00
key: 04 00 00 00  value: 00 00 00 00
Found 5 elements
```

`BPFTool`提供最强大选项之一是可以将预创建映射附加到新程序，使用这些预分配映射替换初始化映射。这样，即使没有编写从`BPF`文件系统中读取映射的程序，也可以从头开始让程序访问到保存的数据。为了实现这个目的，当使用`BPFTool`加载程序时，需要设置需要初始化的映射。当程序加载映射时，可以通过标识符的顺序指定程序的映射。例如，0是第一个映射，1是第二个映射，以此类推。也可以通过名字指定映射，这样更加方便：

```shell
# bpftool prog bpf_prog.o /sys/fs/bpf/bp_prog_2 map name counter /sys/fs/bpf/counter
```

示例中，我们将创建新的映射附加到程序上。在该情况下，我们知道程序初始化的映射名位 `counter` ，所以这里使用名字替换映射。如果更容易记住映射索引位置，还可以使用映射索引位置关键字 `idx`，如 `idx 0`。

### 六、查看附加到特性接口的程序

有时你想知道在特定接口上附加了那些程序。`BPF` 可以加载运行在 `cgroup、perf` 事件和网络数据包上的程序，反过来，`BPFTool`子命令 `cgroup`，`perf`和`net`	可以查看跟踪在这些接口上的附加程序。

`BPFTool`的`perf`子命令可以列出系统中附加到跟踪点的所有程序，例如，`BPFTool`的`perf`子命令可以列出附加到 `kprobes、uprobes`和跟踪点上的所有程序。可以通过`bpftool perf show`来查看。

`BPFTool`的`net`子命令可以列出附加到`XDP`和流量控制的程序。对于其他的像套接字过滤器和端口重用程序的附加程序，只能通过使用 `iproute2`得到。与查看其他`BPF`对象一样，可以通过使用 `bpftool net show` 列出附加到 `XDP` 和 `TC`的程序。

最后，`BPFTool` 的 `cgroup` 子命令可以列出附加到`cgroups` 的所有程序。这个子命令与看到的其他命令有所不同。命令 `bpftool cgroup show` 需要加上查看的 `cgroup`路径。如果想要列出系统中的所有 `cgroup`上的附加程序，需要使用命令 `bpftool cgroup tree`，如：

```shell
CgroupPath
ID       AttachType      AttachFlags     Name
/sys/fs/cgroup/system.slice/systemd-udevd.service
    10       cgroup_inet_ingress multi
    9        cgroup_inet_egress multi
    8        cgroup_device   multi
... ...
/sys/fs/cgroup/system.slice/redis-server.service
    25       cgroup_device   multi
/sys/fs/cgroup/system.slice/upower.service
```

`BPFTool`提供对 `cgroup Perf`和网络接口便捷查看，你可以验证程序是否成功的附加到内核中的任何接口。

### 七、批量加载接口

当你打算分析一个或多个系统行为时，反复运行一些命令是很常见。你可以收集一些经常使用的命令并放入你的工具箱。如果不想每次都键入这些命令，可以使用 `BPFTool`的批量处理模式。

使用批处理模式，可以将要执行的所有命令写在文件中，一起运行所有命令。也可以通过以 `#` 开头的行在文件中增加注释。然而，这种执行模式不是原子的。`BPFTool` 逐行执行命令，如果其中一个命令失败，它将终止执行。系统的状态会保持最新成功运行的命令后的状态。

批处理模式能够处理的简短的文件示例：

```shell
# create a new hash map
map create /sys/fs/bpf/hash_map type hash key 4 value 4 entries 5 name hash_map
# Now show all the maps in the system
map show
```

将这些命令保存在 `/tmp/batch_example.txt`中，可以使用 `bpftool batch file /tmp/batch_example.txt`加载它。首次运行命令你将获得类似下面的输出。再次运行，因为系统中已经存在名为 `hash_map` 映射，该命令将退出，没有任何输出，批处理将在执行第一行时失败：

```shell
# bpftool batch file /tmp/batch_example.txt
2: prog_array  name hid_jmp_table  flags 0x0
        key 4B  value 4B  max_entries 1024  memlock 8512B
        owner_prog_type tracing  owner jited
3: hash  flags 0x0
        key 9B  value 1B  max_entries 500  memlock 59360B
4: hash  name hash_map  flags 0x0
        key 4B  value 4B  max_entries 5  memlock 14592B
processed 2 commands
```

### 八、显示`BTF`信息

`BPFTool` 可以显示任何给定的二进制对象的`BTF` 类型格式（`BTF`）信息。`BTF` 使用元数据信息来注释程序结构，可以用来帮助调试程序。

例如，添加关键字 `linum` 到 `prog dump`中，可以提供源文件和 `BPF`	程序中每条指令的行号。

最新版本`BPFTool`包括新的子命令`btf`，该命令初始用于可视化结构类型。例如`bpftool btf dump id 6` ，显示 `ID`为 54 的程序加载所有 `BTF`类型。
