# eBPF Syscall

## bpf() 子命令参考

`bpf()`系统调用要执行的操作由`cmd`参数确定。每个操作都有一个伴随参数，该参数通过`attr`提供，`attr`是指向`bpf_attr`类型联合体的指针（见下文）。`size`参数是`attr`指向的联合体的大小。

| 宏 | 内核版本(4.19 - 至今) | 提交 |
|:----|:----------|:-----|
|BPF_MAP_CREATE						|√		|[99c55f7d47c0](https://github.com/torvalds/linux/commit/99c55f7d47c0dc6fc64729f37bf435abf43f4c60)|
|BPF_MAP_LOOKUP_ELEM,				|√		|[db20fd2b0108](https://github.com/torvalds/linux/commit/db20fd2b01087bdfbe30bce314a198eefedcc42e)|
|BPF_MAP_UPDATE_ELEM,				|√		|[db20fd2b0108](https://github.com/torvalds/linux/commit/db20fd2b01087bdfbe30bce314a198eefedcc42e)|
|BPF_MAP_DELETE_ELEM,				|√		|[db20fd2b0108](https://github.com/torvalds/linux/commit/db20fd2b01087bdfbe30bce314a198eefedcc42e)|
|BPF_MAP_GET_NEXT_KEY,				|√		|[db20fd2b0108](https://github.com/torvalds/linux/commit/db20fd2b01087bdfbe30bce314a198eefedcc42e)|
|BPF_PROG_LOAD,						|√		|[09756af46893](https://github.com/torvalds/linux/commit/09756af46893c18839062976c3252e93a1beeba7)|
|BPF_OBJ_PIN,						|√		|[b2197755b263](https://github.com/torvalds/linux/commit/b2197755b2633e164a439682fb05a9b5ea48f706)|
|BPF_OBJ_GET,						|√		|[b2197755b263](https://github.com/torvalds/linux/commit/b2197755b2633e164a439682fb05a9b5ea48f706)|
|BPF_PROG_ATTACH,					|√		|[f4324551489e](https://github.com/torvalds/linux/commit/f4324551489e8781d838f941b7aee4208e52e8bf)|
|BPF_PROG_DETACH,					|√		|[f4324551489e](https://github.com/torvalds/linux/commit/f4324551489e8781d838f941b7aee4208e52e8bf)|
|BPF_PROG_TEST_RUN,					|√		|[1cf1cae963c2](https://github.com/torvalds/linux/commit/1cf1cae963c2e6032aebe1637e995bc2f5d330f4)|
|BPF_PROG_RUN = BPF_PROG_TEST_RUN,	|√		|[5d67f349590d](https://github.com/torvalds/linux/commit/5d67f349590ddc94b6d4e25f19085728db9de697)|
|BPF_PROG_GET_NEXT_ID,				|√		|[34ad5580f8f9](https://github.com/torvalds/linux/commit/34ad5580f8f9c86cb273ebea25c149613cd1667e)|
|BPF_MAP_GET_NEXT_ID,				|√		|[34ad5580f8f9](https://github.com/torvalds/linux/commit/34ad5580f8f9c86cb273ebea25c149613cd1667e)|
|BPF_PROG_GET_FD_BY_ID,				|√		|[b16d9aa4c2b9](https://github.com/torvalds/linux/commit/b16d9aa4c2b90af8d2c3201e245150f8c430c3bc)|
|BPF_MAP_GET_FD_BY_ID,				|√		|[bd5f5f4ecb78](https://github.com/torvalds/linux/commit/bd5f5f4ecb78e2698dad655645b6d6a2f7012a8c)|
|BPF_OBJ_GET_INFO_BY_FD,			|√		|[1e2709769086](https://github.com/torvalds/linux/commit/1e270976908686ec25fb91b8a34145be54137976)|
|BPF_PROG_QUERY,					|√		|[468e2f64d220](https://github.com/torvalds/linux/commit/468e2f64d220fe2dc11caa2bcb9b3a1e50fc7321)|
|BPF_RAW_TRACEPOINT_OPEN,			|√		|[c4f6699dfcb8](https://github.com/torvalds/linux/commit/c4f6699dfcb8558d138fe838f741b2c10f416cf9)|
|BPF_BTF_LOAD,						|√		|[f56a653c1fd1](https://github.com/torvalds/linux/commit/f56a653c1fd13a197076dec4461c656fd2adec73)|
|BPF_BTF_GET_FD_BY_ID,				|√		|[78958fca7ead](https://github.com/torvalds/linux/commit/78958fca7ead2f81b60a6827881c4866d1ed0c52)|
|BPF_TASK_FD_QUERY,					|√		|[41bdc4b40ed6](https://github.com/torvalds/linux/commit/41bdc4b40ed6fb26c6acc655ed9a243a348709c9)|
|BPF_MAP_LOOKUP_AND_DELETE_ELEM,	|4.20	|[bd513cd08f10](https://github.com/torvalds/linux/commit/bd513cd08f10cbe28856f99ae951e86e86803861)|
|BPF_MAP_FREEZE,					|5.2	|[87df15de441b](https://github.com/torvalds/linux/commit/87df15de441bd4add7876ef584da8cabdd9a042a)|
|BPF_BTF_GET_NEXT_ID,				|5.4	|[1b9ed84ecf26](https://github.com/torvalds/linux/commit/1b9ed84ecf268904d89edf2908426a8eb3b5a4ba)|
|BPF_MAP_LOOKUP_BATCH,				|5.6	|[cb4d03ab499d](https://github.com/torvalds/linux/commit/cb4d03ab499d4c040f4ab6fd4389d2b49f42b5a5)|
|BPF_MAP_LOOKUP_AND_DELETE_BATCH,	|5.6	|[057996380a42](https://github.com/torvalds/linux/commit/057996380a42bb64ccc04383cfa9c0ace4ea11f0)|
|BPF_MAP_UPDATE_BATCH,				|5.6	|[aa2e93b8e58e](https://github.com/torvalds/linux/commit/aa2e93b8e58e18442edfb2427446732415bc215e)|
|BPF_MAP_DELETE_BATCH,				|5.6	|[aa2e93b8e58e](https://github.com/torvalds/linux/commit/aa2e93b8e58e18442edfb2427446732415bc215e)|
|BPF_LINK_CREATE,					|5.7	|[af6eea57437a](https://github.com/torvalds/linux/commit/af6eea57437a830293eab56246b6025cc7d46ee7)|
|BPF_LINK_UPDATE,					|5.7	|[0c991ebc8c69](https://github.com/torvalds/linux/commit/0c991ebc8c69d29b7fc44db17075c5aa5253e2ab)|
|BPF_LINK_GET_FD_BY_ID,				|5.8	|[2d602c8cf40d](https://github.com/torvalds/linux/commit/2d602c8cf40d65d4a7ac34fe18648d8778e6e594)| 
|BPF_LINK_GET_NEXT_ID,				|5.8	|[2d602c8cf40d](https://github.com/torvalds/linux/commit/2d602c8cf40d65d4a7ac34fe18648d8778e6e594)|
|BPF_ENABLE_STATS,					|5.8	|[d46edd671a14](https://github.com/torvalds/linux/commit/d46edd671a147032e22cfeb271a5734703093649)|
|BPF_ITER_CREATE,					|5.8	|[ac51d99bf81c](https://github.com/torvalds/linux/commit/ac51d99bf81caac8d8881fe52098948110d0de68)|
|BPF_LINK_DETACH,					|5.9	|[73b11c2ab072](https://github.com/torvalds/linux/commit/73b11c2ab072d5b0599d1e12cc126f55ee306daf)|
|BPF_PROG_BIND_MAP,					|5.10	|[ef15314aa5de](https://github.com/torvalds/linux/commit/ef15314aa5de955c6afd87d512e8b00f5ac08d06)|

```c
/* BPF syscall commands, see bpf(2) man-page for more details. */

/**
 * DOC: eBPF Syscall Commands
 *
 * BPF_MAP_CREATE
 *	Description
 *		Create a map and return a file descriptor that refers to the
 *		map. The close-on-exec file descriptor flag (see **fcntl**\ (2))
 *		is automatically enabled for the new file descriptor.
 *
 *		Applying **close**\ (2) to the file descriptor returned by
 *		**BPF_MAP_CREATE** will delete the map (but see NOTES).
 *
 *	Return
 *		A new file descriptor (a nonnegative integer), or -1 if an
 *		error occurred (in which case, *errno* is set appropriately).
 *
 * BPF_MAP_LOOKUP_ELEM
 *	Description
 *		Look up an element with a given *key* in the map referred to
 *		by the file descriptor *map_fd*.
 *
 *		The *flags* argument may be specified as one of the
 *		following:
 *
 *		**BPF_F_LOCK**
 *			Look up the value of a spin-locked map without
 *			returning the lock. This must be specified if the
 *			elements contain a spinlock.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_MAP_UPDATE_ELEM
 *	Description
 *		Create or update an element (key/value pair) in a specified map.
 *
 *		The *flags* argument should be specified as one of the
 *		following:
 *
 *		**BPF_ANY**
 *			Create a new element or update an existing element.
 *		**BPF_NOEXIST**
 *			Create a new element only if it did not exist.
 *		**BPF_EXIST**
 *			Update an existing element.
 *		**BPF_F_LOCK**
 *			Update a spin_lock-ed map element.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 *		May set *errno* to **EINVAL**, **EPERM**, **ENOMEM**,
 *		**E2BIG**, **EEXIST**, or **ENOENT**.
 *
 *		**E2BIG**
 *			The number of elements in the map reached the
 *			*max_entries* limit specified at map creation time.
 *		**EEXIST**
 *			If *flags* specifies **BPF_NOEXIST** and the element
 *			with *key* already exists in the map.
 *		**ENOENT**
 *			If *flags* specifies **BPF_EXIST** and the element with
 *			*key* does not exist in the map.
 *
 * BPF_MAP_DELETE_ELEM
 *	Description
 *		Look up and delete an element by key in a specified map.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_MAP_GET_NEXT_KEY
 *	Description
 *		Look up an element by key in a specified map and return the key
 *		of the next element. Can be used to iterate over all elements
 *		in the map.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 *		The following cases can be used to iterate over all elements of
 *		the map:
 *
 *		* If *key* is not found, the operation returns zero and sets
 *		  the *next_key* pointer to the key of the first element.
 *		* If *key* is found, the operation returns zero and sets the
 *		  *next_key* pointer to the key of the next element.
 *		* If *key* is the last element, returns -1 and *errno* is set
 *		  to **ENOENT**.
 *
 *		May set *errno* to **ENOMEM**, **EFAULT**, **EPERM**, or
 *		**EINVAL** on error.
 *
 * BPF_PROG_LOAD
 *	Description
 *		Verify and load an eBPF program, returning a new file
 *		descriptor associated with the program.
 *
 *		Applying **close**\ (2) to the file descriptor returned by
 *		**BPF_PROG_LOAD** will unload the eBPF program (but see NOTES).
 *
 *		The close-on-exec file descriptor flag (see **fcntl**\ (2)) is
 *		automatically enabled for the new file descriptor.
 *
 *	Return
 *		A new file descriptor (a nonnegative integer), or -1 if an
 *		error occurred (in which case, *errno* is set appropriately).
 *
 * BPF_OBJ_PIN
 *	Description
 *		Pin an eBPF program or map referred by the specified *bpf_fd*
 *		to the provided *pathname* on the filesystem.
 *
 *		The *pathname* argument must not contain a dot (".").
 *
 *		On success, *pathname* retains a reference to the eBPF object,
 *		preventing deallocation of the object when the original
 *		*bpf_fd* is closed. This allow the eBPF object to live beyond
 *		**close**\ (\ *bpf_fd*\ ), and hence the lifetime of the parent
 *		process.
 *
 *		Applying **unlink**\ (2) or similar calls to the *pathname*
 *		unpins the object from the filesystem, removing the reference.
 *		If no other file descriptors or filesystem nodes refer to the
 *		same object, it will be deallocated (see NOTES).
 *
 *		The filesystem type for the parent directory of *pathname* must
 *		be **BPF_FS_MAGIC**.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_OBJ_GET
 *	Description
 *		Open a file descriptor for the eBPF object pinned to the
 *		specified *pathname*.
 *
 *	Return
 *		A new file descriptor (a nonnegative integer), or -1 if an
 *		error occurred (in which case, *errno* is set appropriately).
 *
 * BPF_PROG_ATTACH
 *	Description
 *		Attach an eBPF program to a *target_fd* at the specified
 *		*attach_type* hook.
 *
 *		The *attach_type* specifies the eBPF attachment point to
 *		attach the program to, and must be one of *bpf_attach_type*
 *		(see below).
 *
 *		The *attach_bpf_fd* must be a valid file descriptor for a
 *		loaded eBPF program of a cgroup, flow dissector, LIRC, sockmap
 *		or sock_ops type corresponding to the specified *attach_type*.
 *
 *		The *target_fd* must be a valid file descriptor for a kernel
 *		object which depends on the attach type of *attach_bpf_fd*:
 *
 *		**BPF_PROG_TYPE_CGROUP_DEVICE**,
 *		**BPF_PROG_TYPE_CGROUP_SKB**,
 *		**BPF_PROG_TYPE_CGROUP_SOCK**,
 *		**BPF_PROG_TYPE_CGROUP_SOCK_ADDR**,
 *		**BPF_PROG_TYPE_CGROUP_SOCKOPT**,
 *		**BPF_PROG_TYPE_CGROUP_SYSCTL**,
 *		**BPF_PROG_TYPE_SOCK_OPS**
 *
 *			Control Group v2 hierarchy with the eBPF controller
 *			enabled. Requires the kernel to be compiled with
 *			**CONFIG_CGROUP_BPF**.
 *
 *		**BPF_PROG_TYPE_FLOW_DISSECTOR**
 *
 *			Network namespace (eg /proc/self/ns/net).
 *
 *		**BPF_PROG_TYPE_LIRC_MODE2**
 *
 *			LIRC device path (eg /dev/lircN). Requires the kernel
 *			to be compiled with **CONFIG_BPF_LIRC_MODE2**.
 *
 *		**BPF_PROG_TYPE_SK_SKB**,
 *		**BPF_PROG_TYPE_SK_MSG**
 *
 *			eBPF map of socket type (eg **BPF_MAP_TYPE_SOCKHASH**).
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_PROG_DETACH
 *	Description
 *		Detach the eBPF program associated with the *target_fd* at the
 *		hook specified by *attach_type*. The program must have been
 *		previously attached using **BPF_PROG_ATTACH**.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_PROG_TEST_RUN
 *	Description
 *		Run the eBPF program associated with the *prog_fd* a *repeat*
 *		number of times against a provided program context *ctx_in* and
 *		data *data_in*, and return the modified program context
 *		*ctx_out*, *data_out* (for example, packet data), result of the
 *		execution *retval*, and *duration* of the test run.
 *
 *		The sizes of the buffers provided as input and output
 *		parameters *ctx_in*, *ctx_out*, *data_in*, and *data_out* must
 *		be provided in the corresponding variables *ctx_size_in*,
 *		*ctx_size_out*, *data_size_in*, and/or *data_size_out*. If any
 *		of these parameters are not provided (ie set to NULL), the
 *		corresponding size field must be zero.
 *
 *		Some program types have particular requirements:
 *
 *		**BPF_PROG_TYPE_SK_LOOKUP**
 *			*data_in* and *data_out* must be NULL.
 *
 *		**BPF_PROG_TYPE_RAW_TRACEPOINT**,
 *		**BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE**
 *
 *			*ctx_out*, *data_in* and *data_out* must be NULL.
 *			*repeat* must be zero.
 *
 *		BPF_PROG_RUN is an alias for BPF_PROG_TEST_RUN.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 *		**ENOSPC**
 *			Either *data_size_out* or *ctx_size_out* is too small.
 *		**ENOTSUPP**
 *			This command is not supported by the program type of
 *			the program referred to by *prog_fd*.
 *
 * BPF_PROG_GET_NEXT_ID
 *	Description
 *		Fetch the next eBPF program currently loaded into the kernel.
 *
 *		Looks for the eBPF program with an id greater than *start_id*
 *		and updates *next_id* on success. If no other eBPF programs
 *		remain with ids higher than *start_id*, returns -1 and sets
 *		*errno* to **ENOENT**.
 *
 *	Return
 *		Returns zero on success. On error, or when no id remains, -1
 *		is returned and *errno* is set appropriately.
 *
 * BPF_MAP_GET_NEXT_ID
 *	Description
 *		Fetch the next eBPF map currently loaded into the kernel.
 *
 *		Looks for the eBPF map with an id greater than *start_id*
 *		and updates *next_id* on success. If no other eBPF maps
 *		remain with ids higher than *start_id*, returns -1 and sets
 *		*errno* to **ENOENT**.
 *
 *	Return
 *		Returns zero on success. On error, or when no id remains, -1
 *		is returned and *errno* is set appropriately.
 *
 * BPF_PROG_GET_FD_BY_ID
 *	Description
 *		Open a file descriptor for the eBPF program corresponding to
 *		*prog_id*.
 *
 *	Return
 *		A new file descriptor (a nonnegative integer), or -1 if an
 *		error occurred (in which case, *errno* is set appropriately).
 *
 * BPF_MAP_GET_FD_BY_ID
 *	Description
 *		Open a file descriptor for the eBPF map corresponding to
 *		*map_id*.
 *
 *	Return
 *		A new file descriptor (a nonnegative integer), or -1 if an
 *		error occurred (in which case, *errno* is set appropriately).
 *
 * BPF_OBJ_GET_INFO_BY_FD
 *	Description
 *		Obtain information about the eBPF object corresponding to
 *		*bpf_fd*.
 *
 *		Populates up to *info_len* bytes of *info*, which will be in
 *		one of the following formats depending on the eBPF object type
 *		of *bpf_fd*:
 *
 *		* **struct bpf_prog_info**
 *		* **struct bpf_map_info**
 *		* **struct bpf_btf_info**
 *		* **struct bpf_link_info**
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_PROG_QUERY
 *	Description
 *		Obtain information about eBPF programs associated with the
 *		specified *attach_type* hook.
 *
 *		The *target_fd* must be a valid file descriptor for a kernel
 *		object which depends on the attach type of *attach_bpf_fd*:
 *
 *		**BPF_PROG_TYPE_CGROUP_DEVICE**,
 *		**BPF_PROG_TYPE_CGROUP_SKB**,
 *		**BPF_PROG_TYPE_CGROUP_SOCK**,
 *		**BPF_PROG_TYPE_CGROUP_SOCK_ADDR**,
 *		**BPF_PROG_TYPE_CGROUP_SOCKOPT**,
 *		**BPF_PROG_TYPE_CGROUP_SYSCTL**,
 *		**BPF_PROG_TYPE_SOCK_OPS**
 *
 *			Control Group v2 hierarchy with the eBPF controller
 *			enabled. Requires the kernel to be compiled with
 *			**CONFIG_CGROUP_BPF**.
 *
 *		**BPF_PROG_TYPE_FLOW_DISSECTOR**
 *
 *			Network namespace (eg /proc/self/ns/net).
 *
 *		**BPF_PROG_TYPE_LIRC_MODE2**
 *
 *			LIRC device path (eg /dev/lircN). Requires the kernel
 *			to be compiled with **CONFIG_BPF_LIRC_MODE2**.
 *
 *		**BPF_PROG_QUERY** always fetches the number of programs
 *		attached and the *attach_flags* which were used to attach those
 *		programs. Additionally, if *prog_ids* is nonzero and the number
 *		of attached programs is less than *prog_cnt*, populates
 *		*prog_ids* with the eBPF program ids of the programs attached
 *		at *target_fd*.
 *
 *		The following flags may alter the result:
 *
 *		**BPF_F_QUERY_EFFECTIVE**
 *			Only return information regarding programs which are
 *			currently effective at the specified *target_fd*.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_RAW_TRACEPOINT_OPEN
 *	Description
 *		Attach an eBPF program to a tracepoint *name* to access kernel
 *		internal arguments of the tracepoint in their raw form.
 *
 *		The *prog_fd* must be a valid file descriptor associated with
 *		a loaded eBPF program of type **BPF_PROG_TYPE_RAW_TRACEPOINT**.
 *
 *		No ABI guarantees are made about the content of tracepoint
 *		arguments exposed to the corresponding eBPF program.
 *
 *		Applying **close**\ (2) to the file descriptor returned by
 *		**BPF_RAW_TRACEPOINT_OPEN** will delete the map (but see NOTES).
 *
 *	Return
 *		A new file descriptor (a nonnegative integer), or -1 if an
 *		error occurred (in which case, *errno* is set appropriately).
 *
 * BPF_BTF_LOAD
 *	Description
 *		Verify and load BPF Type Format (BTF) metadata into the kernel,
 *		returning a new file descriptor associated with the metadata.
 *		BTF is described in more detail at
 *		https://www.kernel.org/doc/html/latest/bpf/btf.html.
 *
 *		The *btf* parameter must point to valid memory providing
 *		*btf_size* bytes of BTF binary metadata.
 *
 *		The returned file descriptor can be passed to other **bpf**\ ()
 *		subcommands such as **BPF_PROG_LOAD** or **BPF_MAP_CREATE** to
 *		associate the BTF with those objects.
 *
 *		Similar to **BPF_PROG_LOAD**, **BPF_BTF_LOAD** has optional
 *		parameters to specify a *btf_log_buf*, *btf_log_size* and
 *		*btf_log_level* which allow the kernel to return freeform log
 *		output regarding the BTF verification process.
 *
 *	Return
 *		A new file descriptor (a nonnegative integer), or -1 if an
 *		error occurred (in which case, *errno* is set appropriately).
 *
 * BPF_BTF_GET_FD_BY_ID
 *	Description
 *		Open a file descriptor for the BPF Type Format (BTF)
 *		corresponding to *btf_id*.
 *
 *	Return
 *		A new file descriptor (a nonnegative integer), or -1 if an
 *		error occurred (in which case, *errno* is set appropriately).
 *
 * BPF_TASK_FD_QUERY
 *	Description
 *		Obtain information about eBPF programs associated with the
 *		target process identified by *pid* and *fd*.
 *
 *		If the *pid* and *fd* are associated with a tracepoint, kprobe
 *		or uprobe perf event, then the *prog_id* and *fd_type* will
 *		be populated with the eBPF program id and file descriptor type
 *		of type **bpf_task_fd_type**. If associated with a kprobe or
 *		uprobe, the  *probe_offset* and *probe_addr* will also be
 *		populated. Optionally, if *buf* is provided, then up to
 *		*buf_len* bytes of *buf* will be populated with the name of
 *		the tracepoint, kprobe or uprobe.
 *
 *		The resulting *prog_id* may be introspected in deeper detail
 *		using **BPF_PROG_GET_FD_BY_ID** and **BPF_OBJ_GET_INFO_BY_FD**.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_MAP_LOOKUP_AND_DELETE_ELEM
 *	Description
 *		Look up an element with the given *key* in the map referred to
 *		by the file descriptor *fd*, and if found, delete the element.
 *
 *		For **BPF_MAP_TYPE_QUEUE** and **BPF_MAP_TYPE_STACK** map
 *		types, the *flags* argument needs to be set to 0, but for other
 *		map types, it may be specified as:
 *
 *		**BPF_F_LOCK**
 *			Look up and delete the value of a spin-locked map
 *			without returning the lock. This must be specified if
 *			the elements contain a spinlock.
 *
 *		The **BPF_MAP_TYPE_QUEUE** and **BPF_MAP_TYPE_STACK** map types
 *		implement this command as a "pop" operation, deleting the top
 *		element rather than one corresponding to *key*.
 *		The *key* and *key_len* parameters should be zeroed when
 *		issuing this operation for these map types.
 *
 *		This command is only valid for the following map types:
 *		* **BPF_MAP_TYPE_QUEUE**
 *		* **BPF_MAP_TYPE_STACK**
 *		* **BPF_MAP_TYPE_HASH**
 *		* **BPF_MAP_TYPE_PERCPU_HASH**
 *		* **BPF_MAP_TYPE_LRU_HASH**
 *		* **BPF_MAP_TYPE_LRU_PERCPU_HASH**
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_MAP_FREEZE
 *	Description
 *		Freeze the permissions of the specified map.
 *
 *		Write permissions may be frozen by passing zero *flags*.
 *		Upon success, no future syscall invocations may alter the
 *		map state of *map_fd*. Write operations from eBPF programs
 *		are still possible for a frozen map.
 *
 *		Not supported for maps of type **BPF_MAP_TYPE_STRUCT_OPS**.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_BTF_GET_NEXT_ID
 *	Description
 *		Fetch the next BPF Type Format (BTF) object currently loaded
 *		into the kernel.
 *
 *		Looks for the BTF object with an id greater than *start_id*
 *		and updates *next_id* on success. If no other BTF objects
 *		remain with ids higher than *start_id*, returns -1 and sets
 *		*errno* to **ENOENT**.
 *
 *	Return
 *		Returns zero on success. On error, or when no id remains, -1
 *		is returned and *errno* is set appropriately.
 *
 * BPF_MAP_LOOKUP_BATCH
 *	Description
 *		Iterate and fetch multiple elements in a map.
 *
 *		Two opaque values are used to manage batch operations,
 *		*in_batch* and *out_batch*. Initially, *in_batch* must be set
 *		to NULL to begin the batched operation. After each subsequent
 *		**BPF_MAP_LOOKUP_BATCH**, the caller should pass the resultant
 *		*out_batch* as the *in_batch* for the next operation to
 *		continue iteration from the current point.
 *
 *		The *keys* and *values* are output parameters which must point
 *		to memory large enough to hold *count* items based on the key
 *		and value size of the map *map_fd*. The *keys* buffer must be
 *		of *key_size* * *count*. The *values* buffer must be of
 *		*value_size* * *count*.
 *
 *		The *elem_flags* argument may be specified as one of the
 *		following:
 *
 *		**BPF_F_LOCK**
 *			Look up the value of a spin-locked map without
 *			returning the lock. This must be specified if the
 *			elements contain a spinlock.
 *
 *		On success, *count* elements from the map are copied into the
 *		user buffer, with the keys copied into *keys* and the values
 *		copied into the corresponding indices in *values*.
 *
 *		If an error is returned and *errno* is not **EFAULT**, *count*
 *		is set to the number of successfully processed elements.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 *		May set *errno* to **ENOSPC** to indicate that *keys* or
 *		*values* is too small to dump an entire bucket during
 *		iteration of a hash-based map type.
 *
 * BPF_MAP_LOOKUP_AND_DELETE_BATCH
 *	Description
 *		Iterate and delete all elements in a map.
 *
 *		This operation has the same behavior as
 *		**BPF_MAP_LOOKUP_BATCH** with two exceptions:
 *
 *		* Every element that is successfully returned is also deleted
 *		  from the map. This is at least *count* elements. Note that
 *		  *count* is both an input and an output parameter.
 *		* Upon returning with *errno* set to **EFAULT**, up to
 *		  *count* elements may be deleted without returning the keys
 *		  and values of the deleted elements.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_MAP_UPDATE_BATCH
 *	Description
 *		Update multiple elements in a map by *key*.
 *
 *		The *keys* and *values* are input parameters which must point
 *		to memory large enough to hold *count* items based on the key
 *		and value size of the map *map_fd*. The *keys* buffer must be
 *		of *key_size* * *count*. The *values* buffer must be of
 *		*value_size* * *count*.
 *
 *		Each element specified in *keys* is sequentially updated to the
 *		value in the corresponding index in *values*. The *in_batch*
 *		and *out_batch* parameters are ignored and should be zeroed.
 *
 *		The *elem_flags* argument should be specified as one of the
 *		following:
 *
 *		**BPF_ANY**
 *			Create new elements or update a existing elements.
 *		**BPF_NOEXIST**
 *			Create new elements only if they do not exist.
 *		**BPF_EXIST**
 *			Update existing elements.
 *		**BPF_F_LOCK**
 *			Update spin_lock-ed map elements. This must be
 *			specified if the map value contains a spinlock.
 *
 *		On success, *count* elements from the map are updated.
 *
 *		If an error is returned and *errno* is not **EFAULT**, *count*
 *		is set to the number of successfully processed elements.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 *		May set *errno* to **EINVAL**, **EPERM**, **ENOMEM**, or
 *		**E2BIG**. **E2BIG** indicates that the number of elements in
 *		the map reached the *max_entries* limit specified at map
 *		creation time.
 *
 *		May set *errno* to one of the following error codes under
 *		specific circumstances:
 *
 *		**EEXIST**
 *			If *flags* specifies **BPF_NOEXIST** and the element
 *			with *key* already exists in the map.
 *		**ENOENT**
 *			If *flags* specifies **BPF_EXIST** and the element with
 *			*key* does not exist in the map.
 *
 * BPF_MAP_DELETE_BATCH
 *	Description
 *		Delete multiple elements in a map by *key*.
 *
 *		The *keys* parameter is an input parameter which must point
 *		to memory large enough to hold *count* items based on the key
 *		size of the map *map_fd*, that is, *key_size* * *count*.
 *
 *		Each element specified in *keys* is sequentially deleted. The
 *		*in_batch*, *out_batch*, and *values* parameters are ignored
 *		and should be zeroed.
 *
 *		The *elem_flags* argument may be specified as one of the
 *		following:
 *
 *		**BPF_F_LOCK**
 *			Look up the value of a spin-locked map without
 *			returning the lock. This must be specified if the
 *			elements contain a spinlock.
 *
 *		On success, *count* elements from the map are updated.
 *
 *		If an error is returned and *errno* is not **EFAULT**, *count*
 *		is set to the number of successfully processed elements. If
 *		*errno* is **EFAULT**, up to *count* elements may be been
 *		deleted.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_LINK_CREATE
 *	Description
 *		Attach an eBPF program to a *target_fd* at the specified
 *		*attach_type* hook and return a file descriptor handle for
 *		managing the link.
 *
 *	Return
 *		A new file descriptor (a nonnegative integer), or -1 if an
 *		error occurred (in which case, *errno* is set appropriately).
 *
 * BPF_LINK_UPDATE
 *	Description
 *		Update the eBPF program in the specified *link_fd* to
 *		*new_prog_fd*.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_LINK_GET_FD_BY_ID
 *	Description
 *		Open a file descriptor for the eBPF Link corresponding to
 *		*link_id*.
 *
 *	Return
 *		A new file descriptor (a nonnegative integer), or -1 if an
 *		error occurred (in which case, *errno* is set appropriately).
 *
 * BPF_LINK_GET_NEXT_ID
 *	Description
 *		Fetch the next eBPF link currently loaded into the kernel.
 *
 *		Looks for the eBPF link with an id greater than *start_id*
 *		and updates *next_id* on success. If no other eBPF links
 *		remain with ids higher than *start_id*, returns -1 and sets
 *		*errno* to **ENOENT**.
 *
 *	Return
 *		Returns zero on success. On error, or when no id remains, -1
 *		is returned and *errno* is set appropriately.
 *
 * BPF_ENABLE_STATS
 *	Description
 *		Enable eBPF runtime statistics gathering.
 *
 *		Runtime statistics gathering for the eBPF runtime is disabled
 *		by default to minimize the corresponding performance overhead.
 *		This command enables statistics globally.
 *
 *		Multiple programs may independently enable statistics.
 *		After gathering the desired statistics, eBPF runtime statistics
 *		may be disabled again by calling **close**\ (2) for the file
 *		descriptor returned by this function. Statistics will only be
 *		disabled system-wide when all outstanding file descriptors
 *		returned by prior calls for this subcommand are closed.
 *
 *	Return
 *		A new file descriptor (a nonnegative integer), or -1 if an
 *		error occurred (in which case, *errno* is set appropriately).
 *
 * BPF_ITER_CREATE
 *	Description
 *		Create an iterator on top of the specified *link_fd* (as
 *		previously created using **BPF_LINK_CREATE**) and return a
 *		file descriptor that can be used to trigger the iteration.
 *
 *		If the resulting file descriptor is pinned to the filesystem
 *		using  **BPF_OBJ_PIN**, then subsequent **read**\ (2) syscalls
 *		for that path will trigger the iterator to read kernel state
 *		using the eBPF program attached to *link_fd*.
 *
 *	Return
 *		A new file descriptor (a nonnegative integer), or -1 if an
 *		error occurred (in which case, *errno* is set appropriately).
 *
 * BPF_LINK_DETACH
 *	Description
 *		Forcefully detach the specified *link_fd* from its
 *		corresponding attachment point.
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * BPF_PROG_BIND_MAP
 *	Description
 *		Bind a map to the lifetime of an eBPF program.
 *
 *		The map identified by *map_fd* is bound to the program
 *		identified by *prog_fd* and only released when *prog_fd* is
 *		released. This may be used in cases where metadata should be
 *		associated with a program which otherwise does not contain any
 *		references to the map (for example, embedded in the eBPF
 *		program instructions).
 *
 *	Return
 *		Returns zero on success. On error, -1 is returned and *errno*
 *		is set appropriately.
 *
 * NOTES
 *	eBPF objects (maps and programs) can be shared between processes.
 *
 *	* After **fork**\ (2), the child inherits file descriptors
 *	  referring to the same eBPF objects.
 *	* File descriptors referring to eBPF objects can be transferred over
 *	  **unix**\ (7) domain sockets.
 *	* File descriptors referring to eBPF objects can be duplicated in the
 *	  usual way, using **dup**\ (2) and similar calls.
 *	* File descriptors referring to eBPF objects can be pinned to the
 *	  filesystem using the **BPF_OBJ_PIN** command of **bpf**\ (2).
 *
 *	An eBPF object is deallocated only after all file descriptors referring
 *	to the object have been closed and no references remain pinned to the
 *	filesystem or attached (for example, bound to a program or device).
 */
```