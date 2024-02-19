## EBPF 工作核心流程解析

## libbpf 核心结构体关系详解

## Libbpf API 解析 & demo
主要针对 libbpf 0.8.1 版本进行 API 说明
### 一、获取版本信息
```c
LIBBPF_API __u32 libbpf_major_version(void);
LIBBPF_API __u32 libbpf_minor_version(void);
LIBBPF_API const char *libbpf_version_string(void);
```
**功能：**
获取 libbpf 版本信息
**示例：**
```c
#include <stdio.h>
#include <bpf/libbpf.h>
int main()
{
    char res[100];
    uint32_t major = libbpf_major_version();
    uint32_t minor = libbpf_minor_version();
    const char *version = libbpf_version_string();
    sprintf(res, "%u-%u-%s", major, minor, version);
    printf("%s\n", res);
    return 0;
}
```
```c
[root@wsip-70-182-147-69 Test]# ./get_version
0-8-v0.8
```
