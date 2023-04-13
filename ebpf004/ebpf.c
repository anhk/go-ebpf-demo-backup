#include <linux/bpf.h>
#include "inc/bpf_helpers.h"
#include "inc/common.h"

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
//     __type(key, __u32);
//     __type(value, __u32);
//     __uint(pinning, LIBBPF_PIN_BY_NAME);
//     __uint(max_entries, 4);
//     __uint(map_flags, BPF_F_NO_PREALLOC);
//     __array(values, struct {
//         __uint(type, BPF_MAP_TYPE_ARRAY);
//         __uint(key_size, sizeof(__u32));
//         __uint(value_size, sizeof(__u32)*4);
//         __uint(max_entries, 1);
//     });
// } m4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32) * 4);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 1);
} m4 SEC(".maps");

SEC("kprobe/sys_execve")
int bpf_prog(void* ctx)
{
    __u32 k = 0;
    __u32* v = map_lookup_elem(&m4, &k);
    if (v == NULL) {
        return 0;
    }
    bpf_printk("v=%d", v[2]);
    return 0;
}

char __license[] SEC("license") = "GPL";
