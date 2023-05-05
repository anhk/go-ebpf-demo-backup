
#include <sys/types.h>
#include <linux/bpf.h>
#include "../inc/bpf_helpers.h"
#include "../inc/common.h"
#include "../inc/bpf_endian.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct syscalls_enter_openat_args {
    unsigned long long unused;
    long long syscall_nr;
    long long dfd;
    long long filename_ptr;
    long long flags;
    long long mode;
};

// 参考 https://gist.github.com/ii64/1de9b90308ce10654bb7767c7e4d4558
int klog_event(struct syscalls_enter_openat_args *ctx)
{
    bpf_printk("%s", __FUNCTION__);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int sys_enter_open(struct syscalls_enter_openat_args *ctx)
{
    klog_event(ctx);
    return 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
    __array(values, int (void *));
} tail_jmp_map SEC(".maps") = {
    .values = {
        [1] = (void*)&sys_enter_open,
    },
};

SEC("tracepoint/syscalls/sys_enter_openat")
int openat_before_tail(struct syscalls_enter_openat_args *ctx)
{
    bpf_tail_call(ctx, &tail_jmp_map, 1);

    char fmt[] = "no bpf program for syscall %d\n";
    bpf_trace_printk(fmt, sizeof(fmt), 1);
    return 0;
}
