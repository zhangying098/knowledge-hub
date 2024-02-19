// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <sys/mman.h>
#include "trace_helpers.h"

#define DEBUGFS "/sys/kernel/debug/tracing/"
#define MAX_SYMS 300000

static struct ksym syms[MAX_SYMS];
static int sym_cnt;

static int ksym_cmp(const void *p1, const void *p2)
{
    return ((struct ksym *)p1)->addr - ((struct ksym *)p2)->addr;
}

// 加载内核符号表信息
int load_kallsyms(void)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    char func[256], buf[256];
    char symbol;
    void *addr;
    int i = 0;
    if (!f)
        return -ENOENT;
    while (fgets(buf, sizeof(buf), f))
    {
        if (sscanf(buf, "%p %c %s", &addr, &symbol, func) != 3)
            break;
        if (!addr)
            continue;
        syms[i].addr = (long)addr;
        syms[i].name = strdup(func);
        i++;
    }
    fclose(f);
    sym_cnt = i;
    qsort(syms, sym_cnt, sizeof(struct ksym), ksym_cmp);
    return 0;
}

// 根据入参 key 查询符号名
struct ksym *ksym_search(long key)
{
    int start = 0, end = sym_cnt;
    int result;
    /* kallsyms not loaded. return NULL */
    if (sym_cnt <= 0)
        return NULL;
    // 二分法，查找 key （ksym 地址）对应的符号名
    while (start < end)
    {
        size_t mid = start + (end - start) / 2;
        result = key - syms[mid].addr;
        if (result < 0)
            end = mid;
        else if (result > 0)
            start = mid + 1;
        else
            return &syms[mid];
    }
    // 如果查询的地址在 A 和 B 之间（A,B相邻排序），则实际符号名向下获取
    if (start >= 1 && syms[start - 1].addr < key &&
        key < syms[start].addr)
        /* valid ksym */
        return &syms[start - 1];
    /* out of range. return _stext */
    // 不在范围内，则返回第一个符号名
    return &syms[0];
}

// 根据符号名 name 获取对应的地址 addr (此处可以优化，考虑二分)
long ksym_get_addr(const char *name)
{
    int i;
    for (i = 0; i < sym_cnt; i++)
    {
        if (strcmp(syms[i].name, name) == 0)
            return syms[i].addr;
    }
    return 0;
}

/* open kallsyms and read symbol addresses on the fly. Without caching all
symbols,
* this is faster than load + find.
*/
// 替代上述的 load + find 方式，直接去查询 /proc/kallsyms 获取 sym name 对应的地址
int kallsyms_find(const char *sym, unsigned long long *addr)
{
    char type, name[500];
    unsigned long long value;
    int err = 0;
    FILE *f;
    f = fopen("/proc/kallsyms", "r");
    if (!f)
        return -EINVAL;
    while (fscanf(f, "%llx %c %499s%*[^\n]\n", &value, &type, name) > 0)
    {
        if (strcmp(name, sym) == 0)
        {
            *addr = value;
            goto out;
        }
    }
    err = -ENOENT;
out:
    fclose(f);
    return err;
}

void read_trace_pipe(void)
{
    int trace_fd;
    // 打开 debugfs 的 trace_pipe 文件，读取内核跟踪信息
    trace_fd = open(DEBUGFS "trace_pipe", O_RDONLY, 0);
    if (trace_fd < 0)
        return;
    while (1)
    {
        static char buf[4096];
        ssize_t sz;
        // 读取数据并输出到终端
        sz = read(trace_fd, buf, sizeof(buf) - 1);
        if (sz > 0)
        {
            buf[sz] = 0;
            puts(buf);
        }
    }
}