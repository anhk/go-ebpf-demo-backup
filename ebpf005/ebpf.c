#include <linux/bpf.h>
#include "../inc/bpf_helpers.h"
#include "../inc/common.h"

struct event {
    int pid;
    int uid;
    int foo;
    int bar;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 4096);
} events SEC(".maps");

SEC("kprobe/sys_execve")
int bpf_prog(void* ctx)
{
    struct event event;
//    u32 uid = (u32)bpf_get_current_uid_gid();
//    u32 pid = (u32)bpf_get_current_pid_tgid();

    u32 pid = 0x01020304;
    u32 uid = 0x05060708;

    event.pid = (int)pid;
    event.uid = (int)uid;
    event.foo = 0x0a0b0c0d;
    event.bar = 0x09090909;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    bpf_printk("hello world: %d %d", pid, uid);
    return 0;
}



char __license[] SEC("license") = "GPL";
