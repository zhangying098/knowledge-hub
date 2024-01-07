## BPF 的 LSM 钩子

LSM 实现了钩子的概念，不依赖于系统架构对系统事件进行控制。从技术上讲，挂钩调用类似于系统调用，但是 LSM 挂钩调用与系统独立，并于LSM框架集成，LSM框架提供了方便使用的抽象层，并且在不同体系结构上使用系统调用，避免了可能发生的各种麻烦。

### BPF LSM 模块加载

在 `security/bpf/hooks.c` 函数中，完成 BPF LSM 加载
```c
#include <linux/lsm_hooks.h>
// 罗列了各个hook点
#include <linux/bpf_lsm.h>

static struct security_hook_list bpf_lsm_hooks[] __lsm_ro_after_init = {
	// bpf 对应钩子函数的实现函数为 钩子函数名称前加 bpf_lsm_
	// LSM_HOOK_INIT 对成员的 .head 和 .hook 进行初始化操作
	/*

	{.head = &security_hook_heads.NAME, .hook = {.NAME = bpf_lsm_##NAME}}
	{.head = &security_hook_heads.binder_set_context_mgr, .hook = {.binder_set_context_mgr = bpf_lsm_binder_set_context_mgr}}
	
	*/
	#define LSM_HOOK(RET, DEFAULT, NAME, ...) LSM_HOOK_INIT(NAME, bpf_lsm_##NAME),
	#include <linux/lsm_hook_defs.h>
	#undef LSM_HOOK

	/*
		inode_free_security 是在 inode 对象被释放时调用的安全钩子，
		用于清理与该 inode 相关的安全信息。bpf_inode_storage_free 
		函数实现了该钩子的功能。

		task_free 是在进程对象被释放时调用的安全钩子，用于清理与该
		进程相关的安全信息。bpf_task_storage_free 函数实现了该钩子
		的功能。
	*/
	/*
	{.head = &security_hook_heads.inode_free_security, .hook = {.inode_free_security = bpf_inode_storage_free}}
	{.head = &security_hook_heads.task_free, .hook = {.task_free = bpf_task_storage_free}}
	*/
	LSM_HOOK_INIT(inode_free_security, bpf_inode_storage_free),
	LSM_HOOK_INIT(task_free, bpf_task_storage_free),
};

static int __init bpf_lsm_init(void)
{
	security_add_hooks(bpf_lsm_hooks, ARRAY_SIZE(bpf_lsm_hooks), "bpf");
	pr_info("LSM support for eBPF active\n");
	return 0;
}

struct lsm_blob_sizes bpf_lsm_blob_sizes __lsm_ro_after_init = {
	.lbs_inode = sizeof(struct bpf_storage_blob),
	.lbs_task = sizeof(struct bpf_storage_blob),
};

DEFINE_LSM(bpf) = {
	.name = "bpf",
	.init = bpf_lsm_init,
	.blobs = &bpf_lsm_blob_sizes
};
```


### 内核有 7 个与BPF程序相关的钩子，而SELinux是唯一实现了它们的内置LSM

> 在 `security\selinux\hooks.c` 的 `struct security_hook_list selinux_hooks[]` 可检索到上述相关的 7 个BPF程序相关的 `security_hook_list` 初始化 

```c
#ifdef CONFIG_SECURITY
// 对执行的BPF系统调用进行初始化检查
extern int security_bpf(int cmd, union bpf_attr *attr, unsigned int size);
// 当内核返回一个映射文件描述符时进行检查
extern int security_bpf_map(struct bpf_map *map, fmode_t fmode);
// 当内核返回一个 ebpf 程序的文件描述符时进行检查
extern int security_bpf_prog(struct bpf_prog *prog);
// 初始化BPF映射的安全字段
extern int security_bpf_map_alloc(struct bpf_map *map);
// 清除 BPF 映射中的安全字段
extern void security_bpf_map_free(struct bpf_map *map);
// 初始化 BPF 程序中的安全字段
extern int security_bpf_prog_alloc(struct bpf_prog_aux *aux);
// 清除 BPF 程序中的安全字段
extern void security_bpf_prog_free(struct bpf_prog_aux *aux);
#else
```
LSM BPF 钩子思想是为 eBPF 对象提供对象级的保护，确保只有那些具有适当权限的程序才可以对映射和程序进行操作。


