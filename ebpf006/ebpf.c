#include <linux/bpf.h>
#include "../inc/bpf_helpers.h"
#include "../inc/common.h"



// IPv4 Maglev 查找表定义
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __array(values, struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(key_size, sizeof(__u32)); // 查找表的Hash索引，keytype与valuetype只能是u32
        __uint(value_size, sizeof(__u32) * 32767); // Backend的索引
        __uint(max_entries, 1);
    });
} maglve_map4 SEC(".maps");


SEC("kprobe/sys_execve")
int bpf_prog(void* ctx)
{
    __u32 key = 9;

    void *svc = map_lookup_elem(&maglve_map4, &key);
    if (svc == NULL) {
        return 0;
    }

    __u32 zero = 0;
    __u32 *m = map_lookup_elem(svc, &zero);
    if (m == NULL) {
        bpf_printk("not expected NULL");
        return 0;
    }

    bpf_printk("%u", m[10]);
    return 0;
}


char __license[] SEC("license") = "GPL";
