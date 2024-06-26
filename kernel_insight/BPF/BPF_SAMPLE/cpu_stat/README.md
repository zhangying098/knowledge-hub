CPU在有运行任务时处于活动状态，并且CPU频率调节器可以根据不同的工作负载选择不同的操作点（OPP）；我们使用“pstate”来表示具有特定OPP的运行任务的CPU状态。另一方面，当CPU处于空闲状态时，上面只有一个空闲任务，CPU空闲调节器可以选择一个特定的空闲状态来关闭硬件逻辑；我们使用“cstate”来表示CPU空闲状态。

基于跟踪事件'cpu_idle'和'cpu_frequency'，我们可以完成每个状态的持续时间统计。每当CPU进入或退出空闲状态时，都会记录跟踪事件'cpu_idle'；跟踪事件'cpu_frequency'记录CPU OPP更改的事件，因此很容易知道CPU停留在指定OPP中的时间有多长，并且CPU一定不处于任何空闲状态。

此补丁是为了利用上述跟踪事件进行pstate和cstate统计。为了获得更准确的分析数据，程序使用以下顺序来确保不会错过CPU的运行/空闲时间：

在对用户空间程序进行分析之前，程序首先唤醒所有CPU一次，以避免漏算CPU长时间处于空闲状态的时间；程序强制将'scaling_max_freq'设置为最低频率，然后恢复'scaling_max_freq'到最高频率，这可以确保在开始运行工作负载后，频率可以轻松地更改为更高的频率；

用户空间程序每隔5秒读取映射数据并更新统计信息，这与其他样本bpf程序相同，以避免bpf程序本身引入的大负载；

当发送信号以终止程序时，信号处理程序唤醒所有CPU，将频率设置为最低频率，然后恢复最高频率到'scaling_max_freq'；这与第一步完全相同，以避免在最后阶段漏算CPU的pstate和cstate时间。最后，它报告最新的统计信息。

该程序已在搭载八核CA53 CPU的Hikey板上进行了测试，下面是一个统计结果示例，格式主要遵循Jesper Dangaard Brouer的建议。