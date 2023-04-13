
#include <linux/bpf.h>
#include "inc/bpf_helpers.h"
#include "inc/common.h"

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
    __u32 key = 1;
    void* svc = map_lookup_elem(&m4, &key);
    if (svc == NULL) { // not found
        return 0;
    }
    bpf_printk("find.");
    // bpf_printk("hello ebpf.");

    __u32 k2 = 100;
    void* v = map_lookup_elem(svc, &k2);
    if (v == NULL) {
        return 0;
    }
    bpf_printk("v=%d", *(__u32*)v);

    return 0;
}

char __license[] SEC("license") = "GPL";
