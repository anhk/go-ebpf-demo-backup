#include <linux/bpf.h>
#include "../inc/bpf_helpers.h"
#include "../inc/common.h"

#define IPPROTO_TCP 6
#define AF_INET 2
#define AF_INET6 10

struct trace_event_raw_inet_sock_set_state__stub {
    __u64 unused;
    void* skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol; // FIMXE: 自kernel 5.0.6以上，protocol升级为2字节
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

// kernel: include/trace/events/sock.h
SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(void* ctx)
{
    struct trace_event_raw_inet_sock_set_state__stub args = {};
    if (bpf_probe_read(&args, sizeof(args), ctx) < 0) {
        bpf_printk("read < 0");
        return 0;
    }
    if (args.protocol != IPPROTO_TCP) {
        bpf_printk("proto: %d", args.protocol);
        return 0;
    }

    // 只统计oldstate == SYN_SENT的连接
    if (args.oldstate != BPF_TCP_SYN_SENT) {
        return 0;
    }

    if (args.newstate == BPF_TCP_ESTABLISHED) {
        bpf_printk("connection is established success");
    } else if (args.newstate == BPF_TCP_CLOSE) {
        bpf_printk("connection is failed");
    }

    if (args.family == AF_INET) {
        bpf_printk("  it's ipv4, [%pI4 -> %pI4]", args.saddr, args.daddr);
    } else if (args.family == AF_INET6) {
        bpf_printk("  it's ipv6, [%pI6 -> %pI6]", args.saddr, args.daddr);
    }

    return 0;
}

char __license[] SEC("license") = "GPL";
