## 延迟调优
### 一、关闭定时器迁移
- 场景：延迟敏感场景
- 效果：防止定时器迁移到业务进程所在的隔离核

**配置使用：**

`echo 0 > /proc/sys/kernel/timer_migration`

### 二、消除 numa_balancing pagefault 干扰
- 场景：延迟敏感场景
- 效果：访问cpu本地内存，降低 pagefault 中断

**配置使用：**

`echo 0 > /proc/sys/kernel/numa_balancing`
> numa_balancing 存在跨 numa 节点内存访问， numa_balancing 会触发 pagefault 中断处理

### 三、消除 rcu 加速机制 IPI 中断干扰
- 场景：延迟敏感场景
- 效果：rcu 加速机制会使用 IPI 中断发送到隔离核

**配置使用：**

关闭 rcu 加速： `echo 1 > /sys/kernel/rcu_normal`
> 在一些文件系统卸载，网卡、磁盘等设备删除流程中，会有rcu加速同步等待流程，如果关闭rcu加速，用普通的rcu等待，时间较长。

### 四、关闭 KSM 
- 场景：延迟敏感场景
- 效果：ksm 将导致 pagefault 干扰

**配置使用：**

`echo 0 > /sys/kernel/mm/ksm/merge_across_nodes`

`echo 0 > /sys/kernel/mm/ksm/run`
> ksm 使内核能够检查两个或多个已运行程序并比较它们的内存。如果任何内存区域或页面相同，则ksm将多个相同内存页合并为单个页面。

## 网络调优
## IO调优