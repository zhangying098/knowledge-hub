## `eBPF Syscall`

### `bpf() `子命令参考

`bpf()`系统调用要执行的操作由`cmd`参数确定。每个操作都有一个伴随参数，该参数通过`attr`提供，`attr`是指向`bpf_attr`类型联合体的指针（见下文）。`size`参数是`attr`指向的联合体的大小。

**BPF_MAP_CREATE**
**描述**
		创建一个映射并返回一个指向该映射的文件描述符。关闭执行时文件描述符标志（参见 `fcntl(2)`）将自动对新文件描述符启用。
				
		对 `BPF_MAP_CREATE` 返回的文件描述符应用 `close(2)` 将删除该映射（但请参阅注释）。

**返回值** 
		一个新的文件描述符（非负整数），如果发生错误则返回 -1（此时 `errno` 会被适当设置）。

**BPF_MAP_LOOKUP_ELEM**
**描述**
		在由文件描述符 `map_fd `引用的映射中查找具有给定键的元素。

​		`flags` 参数可以指定为以下之一：
​				**BPF_F_LOCK **
​				在不返回锁的情况下查找自旋锁映射的值。如果元素包含自旋锁，则必须指定此标志。

**返回值 **
		成功时返回零。发生错误时，返回 -1 并适当设置 `errno`。

**BPF_MAP_UPDATE_ELEM**
**描述**
		在指定的映射中创建或更新一个元素（键值对）。

​		`flags`参数应指定为以下之一：
​				**BPF_ANY**
​				创建新元素或更新现有元素。

​				**BPF_NOEXIST**
​				仅当元素不存在时才创建新元素。

​				**BPF_EXIST**
​				更新现有元素。

​				**BPF_F_LOCK**
​				更新带有自旋锁的映射元素。

**返回值**
		成功时返回零。发生错误时返回-1，并适当设置`errno`。

​		可能将`errno`设置为`EINVA、EPERM、ENOMEM、E2BIG、EEXIST`或`NOENT`。
​		**E2BIG**
​		映射中的元素数量已达到在映射创建时指定的max_entries限制。

​		**EEXIST**
​		如果`flags`指定了`BPF_NOEXIST`，而键对应的元素已存在于映射中。

​		**ENOENT**
​		如果`flags`指定了`BPF_EXIST`，而键对应的元素在映射中不存在。

**BPF_MAP_DELETE_ELEM**
**描述** 
		在指定的映射中，通过键查找并删除一个元素。

**返回值**
		成功时返回零。发生错误时返回-1，并适当设置`errno`。

**BPF_MAP_GET_NEXT_KEY**
**描述**
		在指定的映射中，通过键查找一个元素，并返回下一个元素的键。可用于遍历映射中的所有元素。

**返回值**
		成功时返回零。发生错误时返回-1，并适当设置`errno`。

​		以下情况可用于遍历映射中的所有元素：
​			如果未找到键，操作返回零，并将next_key指针设置为第一个元素的键。
​			如果找到键，操作返回零，并将next_key指针设置为下一个元素的键。
​			如果键是最后一个元素，返回-1，并将`errno`设置为`ENOENT`。
​			发生错误时，可能将`errno`设置为`ENOMEM、EFAULT、EPERM`或`EINVAL`。

**BPF_PROG_LOAD**
**描述**
		验证并加载一个`eBPF`程序，返回与该程序关联的新文件描述符。

​		对`BPF_PROG_LOAD`返回的文件描述符应用`close(2)`将卸载`eBPF`程序（但请参见注意事项）。

​		新文件描述符会自动启用close-on-exec文件描述符标志（参见`fcntl(2)`）。

**返回值**
		成功时返回新的文件描述符（一个非负整数），如果发生错误则返回-1（在这种情况下，会适当设置`errno`）。

**BPF_OBJ_PIN**
**描述**
		将指定的`bpf_fd`引用的`eBPF`程序或映射固定到文件系统中的给定路径名。

​		pathname`参数中不得包含点`(".")`。

​		成功时，`pathname`将保留对`eBPF`对象的引用，从而防止在关闭原始`bpf_fd`时释放该对象。
​		这允许`eBPF`对象在`close(bpf_fd)`之后以及父进程的生命周期内继续存在。

​		对`pathname`应用`unlink(2)`或类似的调用将取消对象在文件系统中的固定，并移除引用。
​		如果没有其他文件描述符或文件系统节点引用相同的对象，则该对象将被释放（请参见注意事项）。

​		`pathname`的父目录的文件系统类型必须是`BPF_FS_MAGIC`。

**返回值**
		成功时返回零。发生错误时返回-1，并适当设置`errno`。

**BPF_OBJ_GET**
**描述**
		为固定到指定`pathname`的`eBPF`对象打开一个文件描述符。

**返回值**
		成功时返回新的文件描述符（一个非负整数），如果发生错误则返回-1（在这种情况下，会适当设置`errno`）。

**BPF_PROG_ATTACH**
	描述
				将`eBPF`程序附加到指定`attach_type`挂钩的`target_fd`上。

​				`attach_type`指定了将程序附加到的`eBPF`附加点，并且必须是`bpf_attach_type`之一（见下文）。

​				`attach_bpf_fd`必须是对应于指定`attach_type`的`cgroup、flow dissector、LIRC、sockmap`或`sock_ops`类型				的已加载`eBPF`程序的有效文件描述符。

​				`target_fd`必须是内核对象的有效文件描述符，该对象依赖于`attach_bpf_fd`的`attach`类型：					
​				**BPF_PROG_TYPE_CGROUP_DEVICE, BPF_PROG_TYPE_CGROUP_SKB,
​				BPF_PROG_TYPE_CGROUP_SOCK, BPF_PROG_TYPE_CGROUP_SOCK_ADDR, 		
​				BPF_PROG_TYPE_CGROUP_SOCKOPT, BPF_PROG_TYPE_CGROUP_SYSCTL, 
​				BPF_PROG_TYPE_SOCK_OPS**

​					启用了`eBPF`控制器的`Control Group v2`层次结构。需要内核使用`CONFIG_CGROUP_BPF`编译。

​				**BPF_PROG_TYPE_FLOW_DISSECTOR**
​					网络命名空间（例如`/proc/self/ns/net`）。

​				**BPF_PROG_TYPE_LIRC_MODE2**
​					`LIRC`设备路径（例如`/dev/lircN`）。需要内核使用`CONFIG_BPF_LIRC_MODE2`编译。

​				**BPF_PROG_TYPE_SK_SKB, BPF_PROG_TYPE_SK_MSG**
​					`eBPF`映射的套接字类型（例如`BPF_MAP_TYPE_SOCKHASH`）。

​		返回值
​				成功时返回零。发生错误时返回-1，并适当设置`errno`。

**BPF_PROG_DETACH**
		描述
				从由`attach_type`指定的挂钩上分离与`target_fd`关联的`eBPF`程序。程序必须之前已经使用
				`BPF_PROG_ATTACH`附加。

​		返回值
​				成功时返回零。发生错误时返回-1，并适当设置`errno`。

**BPF_PROG_TEST_RUN**
		描述
				针对提供的程序上下文`ctx_in`和数据`data_in`，将与`prog_fd`关联的`eBPF`程序重复执行`repeat`次数，并返回
				修改后的程序上下文`ctx_out`、数据`data_out`（例如数据包数据）、执行结果`retval`以及测试运行时长。

​				作为输入和输出参数提供的缓冲区`ctx_in、ctx_out、data_in`和`data_out`的大小必须在相应的变量				
​				`ctx_size_in、ctx_size_out、data_size_in`和/或data_size_out中提供。如果其中任何参数未提供
​				（即设置为NULL），则相应的大小字段必须为零。

​				某些程序类型具有特殊要求：
​				**BPF_PROG_TYPE_SK_LOOKUP**
​						`data_in`和`data_out`必须为`NULL`。

​				**BPF_PROG_TYPE_RAW_TRACEPOINT, BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE**
​						`ctx_out、data_in和data_out`必须为`NULL`。`repeat`必须为零。

​				**BPF_PROG_RUN**是**BPF_PROG_TEST_RUN**的别名。

​		返回值
​				成功时返回零。发生错误时返回-1，并适当设置`errno`。

​				**ENOSPC**
​						`data_size_out`或`ctx_size_out`太小。

​				**ENOTSUPP**
​						由`prog_fd`引用的程序类型不支持此命令。

**BPF_PROG_GET_NEXT_ID**
		**描述**
				获取当前已加载到内核中的下一个`eBPF`程序的`ID`。

​				查找ID大于`start_id`的eBPF程序，并在成功时更新`next_id`。如果没有ID高于`start_id`的其他eBPF程序，
​				返回-1，并将`errno`设置为`ENOENT`。

​		**返回值**
​				成功时返回0。在错误或没有更多ID时，返回-1，并适当设置`errno`。

**BPF_MAP_GET_NEXT_ID**
		**描述**
				获取当前已加载到内核中的下一个eBPF映射的ID。

​				查找ID大于`start_id`的eBPF映射，并在成功时更新`next_id`。如果没有ID高于`start_id`的其他eBPF映射，
​				返回-1，并将`errno`设置为`ENOENT`。

​		**返回值**
​				成功时返回0。在错误或没有更多ID时，返回-1，并适当设置`errno`。

**BPF_PROG_GET_FD_BY_ID**
		**描述**
				通过给定的`prog_id`打开一个与eBPF程序对应的文件描述符。

​		**返回值**
​				成功时返回一个新的非负整数文件描述符。如果发生错误，返回-1，并适当设置`errno`。

**BPF_MAP_GET_FD_BY_ID**
		**描述**
				通过给定的`map_id`打开一个与eBPF映射对应的文件描述符。

​		**返回值**
​				成功时返回一个新的非负整数文件描述符。如果发生错误，返回-1，并适当设置`errno`。

**BPF_OBJ_GET_INFO_BY_FD**
		**描述**
				获取与给定`bpf_fd`对应的eBPF对象的信息。

​				根据`bpf_fd`对应的eBPF对象类型，将最多`info_len`字节的信息填充到`info`中，其格式可以是以下之一：				`struct bpf_prog_info`
​				`struct bpf_map_info`
​				`struct bpf_btf_info`
​				`struct bpf_link_info`

​		**返回值**
​				成功时返回0。如果发生错误，返回-1，并适当设置`errno`。

**BPF_PROG_QUERY**
		**描述**
				获取与指定`attach_type`挂钩关联的eBPF程序的信息。

​				`target_fd`必须是对于内核对象的有效文件描述符，该对象依赖于`attach_bpf_fd`的附加类型：	
​					`BPF_PROG_TYPE_CGROUP_DEVICE`, `BPF_PROG_TYPE_CGROUP_SKB`, `BPF_PROG_TYPE_CGROUP_SOCK`, 				
​					`BPF_PROG_TYPE_CGROUP_SOCK_ADDR`, `BPF_PROG_TYPE_CGROUP_SOCKOPT`, `BPF_PROG_TYPE_CGROUP_SYSCTL`, 			
​					`BPF_PROG_TYPE_SOCK_OPS`

​						这些是与控制组v2层次结构相关的程序类型，该层次结构需要启用eBPF控制器。这要求内核是用
​						`CONFIG_CGROUP_BPF`编译的。
​				
​				**BPF_PROG_TYPE_FLOW_DISSECTOR**
​						这是与网络命名空间（例如`/proc/self/ns/net`）相关的程序类型。

​				**BPF_PROG_TYPE_LIRC_MODE2**
​						这是与LIRC设备路径（例如`/dev/lircN`）相关的程序类型，需要内核用`CONFIG_BPF_LIRC_MODE2`编译。

​				**BPF_PROG_QUERY**始终获取附加的程序数量以及用于附加这些程序的`attach_flags`。此外，如果
​				`prog_ids`非零且附加的程序数量少于`prog_cnt`，则使用`target_fd`附加的程序的eBPF程序ID填充
​				`prog_ids`。

​				以下标志可能会改变结果：
​				**BPF_F_QUERY_EFFECTIVE**
​						仅返回与指定`target_fd`当前有效的程序相关的信息。

​		**返回值**
​				成功时返回0。如果发生错误，返回-1，并适当设置`errno`。

**BPF_RAW_TRACEPOINT_OPEN**
		**描述**
				将一个eBPF程序附加到跟踪点名称，以访问跟踪点内核内部参数的原始形式。
				
				`prog_fd`必须是与已加载的`BPF_PROG_TYPE_RAW_TRACEPOINT`类型的eBPF程序关联的有效文件描述符。

​				关于暴露给相应eBPF程序的跟踪点参数的内容，没有应用二进制接口（ABI）保证。

​				对`BPF_RAW_TRACEPOINT_OPEN`返回的文件描述符应用`close(2)`将删除映射（但请参见注意事项）。

​		**返回值**
​				成功时返回一个新的非负整数文件描述符。如果发生错误，返回-1，并适当设置`errno`。

**BPF_BTF_LOAD**
		**描述**
				验证并加载BPF类型格式（BTF）元数据到内核中，并返回一个与元数据关联的新文件描述符。BTF的详细信息
				可以在https://www.kernel.org/doc/html/latest/bpf/btf.html上找到。

​				`btf`参数必须指向包含`btf_size`字节BTF二进制元数据的有效内存。

​				返回的文件描述符可以传递给其他bpf()子命令，如`BPF_PROG_LOAD`或`BPF_MAP_CREATE`，以将这些BTF与那些对
​				象关联起来。

​				与`BPF_PROG_LOAD`类似，`BPF_BTF_LOAD`有可选参数来指定`btf_log_buf`、`btf_log_size`和`btf_log_level`，
​				这些参数允许内核返回关于BTF验证过程的自由格式日志输出。

​		**返回值**
​				成功时返回一个新的非负整数文件描述符。如果发生错误，返回-1，并适当设置`errno`。

**BPF_BTF_GET_FD_BY_ID**
		**描述**
				根据`btf_id`打开与BPF类型格式（BTF）对应的文件描述符。

​		**返回值**
​				成功时返回一个新的非负整数文件描述符。如果发生错误，返回-1，并适当设置`errno`。

**BPF_TASK_FD_QUERY**
		**描述**
				获取与通过`pid`和`fd`标识的目标进程关联的eBPF程序的信息。

​				如果`pid`和`fd`与跟踪点、kprobe或uprobe性能事件关联，则`prog_id`和`fd_type`将被填充为eBPF程序ID和类
​				型为`bpf_task_fd_type`的文件描述符类型。如果与kprobe或uprobe关联，则`probe_offset`和`probe_addr`也将
​				被填充。如果提供了`buf`，则最多`buf_len`字节的`buf`将被填充为跟踪点、kprobe或uprobe的名称。

​				可以使用`BPF_PROG_GET_FD_BY_ID`和`BPF_OBJ_GET_INFO_BY_FD`来更深入地检查返回的`prog_id`。

​		**返回值**
​				成功时返回0。如果发生错误，返回-1，并适当设置`errno`。

**BPF_MAP_LOOKUP_AND_DELETE_ELEM**
		**描述**
				在由文件描述符`fd`引用的映射中查找具有给定键的元素，如果找到，则删除该元素。

​				对于`BPF_MAP_TYPE_QUEUE`和`BPF_MAP_TYPE_STACK`映射类型，`flags`参数需要设置为0，但对于其他映射类型，
​				可以指定为：
​				**BPF_F_LOCK**
​						查找并删除自旋锁映射的值，但不返回锁。如果元素包含自旋锁，则必须指定此标志。

​				**BPF_MAP_TYPE_QUEUE**和**BPF_MAP_TYPE_STAC**映射类型将此命令实现为“弹出”操作，删除顶部元素
​				而不是与键对应的元素。对于这些映射类型，在发出此操作时，应将`key`和`key_len`参数设置为零。

​				此命令仅对以下映射类型有效：		
​				`BPF_MAP_TYPE_QUEUE`,`BPF_MAP_TYPE_STACK`,`BPF_MAP_TYPE_HASH`,`BPF_MAP_TYPE_PERCPU_HASH`,
​				`BPF_MAP_TYPE_LRU_HASH`,`BPF_MAP_TYPE_LRU_PERCPU_HASH`

​		**返回值**
​				成功时返回0。如果发生错误，返回-1，并适当设置`errno`。

**BPF_MAP_FREEZE**
		**描述**
				冻结指定映射的权限。

​				通过将标志设置为零，可以冻结写权限。成功后，未来的系统调用将无法更改`map_fd`映射的状态。对于已冻
​				结的映射，eBPF程序仍然可以进行写操作。

​				不支持`BPF_MAP_TYPE_STRUCT_OPS`类型的映射。

​		**返回值**
​				成功时返回0。如果发生错误，返回-1，并适当设置`errno`。

**BPF_BTF_GET_NEXT_ID**
		**描述**
				获取当前已加载到内核中的下一个BPF类型格式（BTF）对象。

​				查找ID大于`start_id`的BTF对象，并在成功时更新`next_id`。如果没有其他ID高于`start_id`的BTF对象，
​				则返回-1，并将`errno`设置为`ENOENT`。

​		**返回值**
​				成功时返回0。如果发生错误或没有剩余ID，返回-1，并适当设置`errno`。

**BPF_MAP_UPDATE_BATCH**
		**描述**
				根据键在映射中更新多个元素。

​				键和值是输入参数，它们必须指向足够大的内存，以基于映射`map_fd`的键和值大小容纳`count`个项。
​				键缓冲区的大小必须是`key_size * count`。值缓冲区的大小必须是`value_size * count`。

​				在键中指定的每个元素都将按顺序更新为值中对应索引处的值。`in_batch`和`out_batch`参数被忽略，
​				并应设置为零。

​				`elem_flags`参数应指定为以下之一：
​				**BPF_ANY**
​				创建新元素或更新现有元素。
​				
​				**BPF_NOEXIST**
​				仅当它们不存在时创建新元素。

​				**BPF_EXIST**
​				更新现有元素。

​				**BPF_F_LOCK**
​				更新自旋锁映射的元素。如果映射值包含自旋锁，则必须指定此标志。

​				成功时，映射中的`count`个元素将被更新。

​				如果返回错误且`errno`不是`EFAULT`，则`count`将设置为成功处理的元素数量。

​		**返回值**
​				成功时返回0。如果发生错误，返回-1，并适当设置`errno`。

​				可能会将`errno`设置为`EINVAL`、`EPERM`、`ENOMEM`或`E2BIG`。`E2BIG`表示映射中的元素数量已达到在映射创建
​				时指定的`max_entries`限制。

​				在特定情况下，可能会将`errno`设置为以下错误代码之一：
​				**EEXIST**
​				如果`flags`指定了`BPF_NOEXIST`，并且具有该键的元素已存在于映射中。

​				**ENOENT**
​				如果`flags`指定了`BPF_EXIST`，并且具有该键的元素不存在于映射中。

**BPF_MAP_DELETE_BATCH**
		**描述**
				根据键在映射中删除多个元素。

​				`keys`参数是一个输入参数，它必须指向足够大的内存，以基于映射`map_fd`的键大小容纳`count`个项，
​				即`key_size * count`。

​				在`keys`中指定的每个元素都将按顺序删除。`in_batch`、`out_batch`和`values`参数被忽略，并应设置为零。

​				`elem_flags`参数可以指定为以下之一：
​				**BPF_F_LOCK**
​						查找自旋锁映射的值但不返回锁。如果元素包含自旋锁，则必须指定此标志。

​						成功时，映射中的`count`个元素将被更新。

​						如果返回错误且`errno`不是`EFAULT`，则`count`将设置为成功处理的元素数量。如果`errno`是`EFAULT`，
​						则可能已删除最多`count`个元素。

​		**返回值**
​				成功时返回0。如果发生错误，返回-1，并适当设置`errno`。

**BPF_LINK_CREATE**
		**描述**
				将eBPF程序附加到具有指定`attach_type`挂钩的`target_fd`，并返回一个用于管理链接的文件描述符句柄。

​		**返回值**
​				如果成功，返回一个新的文件描述符（一个非负整数）。如果发生错误，返回-1（在这种情况下，会适当设
​				置`errno`）。

**BPF_LINK_UPDATE**
		**描述**
				更新指定`link_fd`中的eBPF程序为`new_prog_fd`。

​		**返回值**
​				成功时返回0。如果发生错误，返回-1，并适当设置`errno`。

**BPF_LINK_GET_FD_BY_ID**
		**描述**
				为对应于`link_id`的eBPF Link打开一个文件描述符。

​		**返回值**
​				如果成功，返回一个新的文件描述符（一个非负整数）。如果发生错误，返回-1，并适当设置`errno`。

**BPF_LINK_GET_NEXT_ID**
		**描述**
				获取当前加载到内核中的下一个eBPF链接。

​				查找id大于`start_id`的eBPF链接，并在成功时更新`next_id`。如果没有其他id高于`start_id`的eBPF链接
​				存在，则返回-1并将`errno`设置为`ENOENT`。

​	**返回值**
​				成功时返回0。当没有更多id或发生错误时，返回-1，并适当设置`errno`。

**BPF_ENABLE_STATS**
		**描述**
				启用eBPF运行时统计信息的收集。

​				为了最小化相应的性能开销，eBPF运行时的统计信息收集默认是禁用的。此命令全局启用统计信息。

​				多个程序可以独立地启用统计信息。在收集所需的统计信息后，可以通过调用`close(2)`来关闭此函数返回的
​				文件描述符，从而再次禁用eBPF运行时统计信息。只有当通过先前调用此子命令返回的所有未关闭的文件描
​				述符都被关闭时，系统范围内的统计信息才会被禁用。

​		**返回值**
​				如果成功，返回一个新的文件描述符（一个非负整数）。如果发生错误，返回-1，并适当设置`errno`。

**BPF_ITER_CREATE**
		**描述**
				在指定的`link_fd`（先前使用`BPF_LINK_CREATE`创建）上创建一个迭代器，并返回一个文件描述符，
				可用于触发迭代。

​				如果将结果文件描述符使用`BPF_OBJ_PIN`钉住到文件系统，那么后续对该路径的`read(2)`系统调用将触发迭代
​				器使用附加到`link_fd`的eBPF程序来读取内核状态。

​		**返回值**
​				如果成功，返回一个新的文件描述符（一个非负整数）。如果发生错误，返回-1，并适当设置`errno`。

**BPF_LINK_DETACH**
		**描述**
				强制将指定的`link_fd`从其对应的附加点分离。

​		**返回值**
​				成功时返回0。如果发生错误，返回-1，并适当设置`errno`。

**BPF_PROG_BIND_MAP**
		**描述**
				将一个map绑定到一个eBPF程序的生命周期上。

​				由`map_fd`标识的map被绑定到由`prog_fd`标识的程序上，并且只有在`prog_fd`被释放时才会被释放。
​				这可以在需要将元数据与程序相关联的情况下使用，而这些程序本身不包含对map的任何引用（例如，
​				嵌入在eBPF程序指令中）。

​		**返回值**
​				成功时返回0。如果发生错误，返回-1，并适当设置`errno`。

**注意事项**
	eBPF对象（maps和程序）可以在进程之间共享。

  - 在`fork(2)`之后，子进程会继承指向相同eBPF对象的文件描述符。
  - 指向eBPF对象的文件描述符可以通过`unix(7)`域套接字进行传输。
  - 指向eBPF对象的文件描述符可以通过通常的方式使用`dup(2)`和类似的调用进行复制。
  - 指向eBPF对象的文件描述符可以使用`bpf(2)`的`BPF_OBJ_PIN`命令钉住到文件系统。

只有当指向对象的所有文件描述符都被关闭，且没有引用被钉住到文件系统或附加（例如，绑定到程序或设备）时，eBPF对象才会被释放。