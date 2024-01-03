#!/bin/dash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

rm -rf /sys/fs/bpf/lsm_demo
mount bpffs -t bpf /sys/fs/bpf
clang -O2 -g -target bpf -D_TARGET_ARCH_X86_64 -c lsm.bpf.c -o lsm.bpf.o
bpftool prog load lsm.bpf.o /sys/fs/bpf/lsm_demo

if ! command -v jq &>/dev/null; then
    sudo apt install -y jq >/dev/null
fi

ID=$(bpftool prog list | awk '/lsm.*/{print $1}' | tr -d :)
bpftool prog show id ${ID}