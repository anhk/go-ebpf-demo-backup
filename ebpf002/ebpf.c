
#include <linux/bpf.h>
#include "inc/bpf_helpers.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, 1);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __array(values, struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, __u32);
        __type(value, __u32);
        __uint(max_entries, 4096);
    	__uint(map_flags, BPF_F_NO_PREALLOC);
    });
} m4 SEC(".maps");

SEC("kprobe/sys_execve")
int bpf_prog(void* ctx)
{
    bpf_printk("hello ebpf.");
    return 0;
}

char __license[] SEC("license") = "GPL";
