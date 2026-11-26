//go:build linux

package main

// The object is built from bpf/sensor.c. It needs clang, libbpf headers and bpftool:
//
//	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
//	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I bpf -c bpf/sensor.c -o bpf/sensor_bpfel.o
//
// TODO(56.2): bpf/sensor_bpfel.o is an empty placeholder because clang was unavailable when this
// task was implemented. Regenerate and commit it; until then loadSource reports ErrObjectMissing.
