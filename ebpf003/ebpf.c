#include <linux/bpf.h>
#include "inc/bpf_helpers.h"
#include "inc/common.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, 1);
    __uint(max_entries, 4);
    // __uint(map_flags, BPF_F_NO_PREALLOC);
} m4 SEC(".maps");

SEC("kprobe/sys_execve")
int bpf_prog(void* ctx)
{
    __u32 zero = 0;
    __u32* svc = map_lookup_elem(&m4, &zero);
    if (svc == NULL) { // not found
        return 0;
    }
    bpf_printk("find.");

    __u32 i = 2;
    __u32* v = map_lookup_elem(&m4, &i);
    if (v == NULL) {
        return 0;
    }
    bpf_printk("%d - %d", i, *v);
    return 0;
}

char __license[] SEC("license") = "GPL";
