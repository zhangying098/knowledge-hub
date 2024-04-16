### 设置 grub 参数方法
- `vim /etc/default/grub` 定位到 `GRUB_CMDLINE_LINUX`。
- 在 `GRUB_CMDLINE_LINUX=` 中添加需要的 grub 启动参数。
- `grub2-mkconfig -o /boot/efi/EFI/*/grub.cfg` 在 CentOS系列。`update-grub` 在 Ubuntu 系列。
- 重启系统，执行 `cat /proc/cmdline` 查看配置是否生效

### 一、selinux = 0
- 场景：性能场景
- 效果：减少 SELINUX 带来的性能开销

### 二、audit = 0
- 场景：性能场景
- 效果：减少 audit 带来的性能开销

**功能：**

audit 是一个用于收集记录系统、内核、用户进程发生的一些行为事件的安全审计系统。

### 三、pci = pcie_bus_perf
- 场景：数据大吞吐场景（网络、磁盘）
- 效果：根据PCIe设备的父总线，将设备MPS设置为允许的最大MPS。同时将MRRS（最大读取请求大小）设置为支持的最大值。

> MPS：PCI 设备之间的报文传输使用的TLP（Translation Layer Protocol），TLP报文中Data部分的大小就是Payload , Payload的最大size是由设备的MPS（Max Payload Size）决定的，所以MPS大的话pcie传输效率高一些。

### 四、nohz = on
- 场景：CPU性能场景，非延迟敏感场景
- 效果：当CPU处于空闲时，直接设置下一次的中断时间而不是使用系统默认的HZ中断，开启后对延迟有影响。

> 内核为每一个CPU核设置一个周期性的时钟中断，依赖这个时钟中断处理一些进程时间片等周期性的事件。时钟中断需要消耗CPU，频率越高调度的时间片越小，系统的实时响应能力越强，也会更消耗CPU资源。可以通过 grep ^CONFIG_HZ /boot/config-\`uname -r\`  查看内核时钟周期值。

### 五、nohz = off
- 场景：延迟敏感场景
- 效果：CPU使用周期性的时钟处理进程事件，响应快，但是带来更多CPU开销。

### 六、isolcpus = <cpulist>
- 场景：延迟敏感场景
- 效果：隔离任务所在的CPU核，防止CPU将进程调度到隔离核

### 七、nosoftlockup
- 场景：数据吞吐性能测试
- 效果：禁用软锁检测器

### 八、skew_tick = 1
- 场景：延迟敏感场景
- 效果：增加系统功耗，建议仅在运行抖动敏感工作负载时使用

**功能：**

在多处理器系统中，每个CPU独立地执行周期性定时器 tick。因此，每个CPU可以更新系统时间而无需全局同步。skew_tick 有助于平滑对延迟敏感的应用程序在系统上抖动。RT系统上延迟峰值常见来源是多个CPU争用linux内核计时器ticks处理程序中的公共锁。多CPU试图获取 xtime_lock，当某个CPU已持有xtime_lock并在更新系统时间时，其他CPU也需读取和更新系统时间，就需要等该锁释放，会导致其它CPU阻塞。skew_tick通过使它们的开始时间"倾斜"来确保每个CPU的ticks不会同时发生。

### 九、nohz_full = <cpulist>
- 场景：同 nohz=on
- 效果：当CPU处于空闲状态时，直接设置下一次的中断时间而不是使用系统默认的HZ中断，开启后对延迟有影响。这里可以设置部分核心开启。

### 十、transparent_hugepage = never
- 场景：降低CPU开销
- 效果：使用动态大页将导致CPU开销上涨

### 十一、irqaffinity = <cpulist>
- 场景：延迟敏感场景
- 效果：设置默认中断亲和性，防止中断初始化绑定到隔离核上

**功能：**

在实时场景，实时任务绑定在隔离核上，为防止中断干扰，将中断线程绑定到隔离核外的CPU核上。

### 十二、rcu_nocbs=<cpulist>
- 场景：延迟敏感场景
- 效果：绑定线程处理RCU回调函数

**功能：**

在实时场景，实时任务绑定在隔离核上。rcu线程绑定在其他核心上。会影响非隔离核的性能。

### 十三、intel cstate 
- 场景：延迟敏感场景
- 效果：intel 处理器的 cstate，数值越大，休眠深度越深，唤醒时间越长

**配置使用：**

**processor.max_cstate=0 intel_idle.max_cstate=0**
> 该配置会导致功耗增加

### 十四、idle = poll
- 场景：延迟敏感场景
- 效果：系统强制将处理器的空闲状态设置为轮询模式，不让处理器进入睡眠状态。保证处理器始终处于活跃状态，减少唤醒带来的延迟。

### 十五、mce = off
- 场景：延迟敏感场景
- 效果：减少mce事件中断对业务影响

> 如果发生了CPU硬件异常，可能无法处理导致错误积累，影响扩大

### 十六、pcie_aspm = off
- 场景：延迟敏感场景
- 效果：禁用PCIe设备功耗管理，维持设备高性能运行
