
//go:build ignore
#include <linux/bpf.h>
#include "bpf_helpers.h"

SEC("tracepoint/syscalls/sys_enter_openat")
int bpf_printk_prog(void *ctx){
    char msg[] = "Hello, BPF World!";
    bpf_trace_printk(msg, sizeof(msg));
    bpf_printk("bpf printk msg----------");
    return 0;
}

char __license[] SEC("license") = "GPL";
