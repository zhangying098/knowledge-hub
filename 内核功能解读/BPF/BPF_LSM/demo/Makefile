CC = clang
CFLAGS = -g -O2 -DBPF_NO_PRESERVE_ACCESS_INDEX -D__TARGET_ARCH_x86
LDFLAGS = -lelf -lbpf

all: lsm

clean:
	rm -rf lsm.bpf.o lsm.skel.h lsm lsm.bpf.o

lsm.bpf.o: lsm.bpf.c
	$(CC) $(CFLAGS) -target bpf -c $< -o $@
	llvm-strip -g $@

lsm.skel.h: lsm.bpf.o
	bpftool gen skeleton $< > $@

lsm: lsm.c lsm.skel.h
	$(CC) $< $(LDFLAGS) -o $@