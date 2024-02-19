#！/bin/bash
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c offwaketime_kern.c -o offwaketime_kern.o
clang offwaketime_user.c -lelf -lbpf -o offwaketime