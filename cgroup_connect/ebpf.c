#include <linux/bpf.h>
#include "../inc/bpf_helpers.h"
#include "../inc/common.h"
#include "../inc/bpf_endian.h"

#define SYS_REJECT	0
#define SYS_PROCEED	1

SEC("cgroup/connect4")
int sock_connect4(struct bpf_sock_addr* ctx)
{
    if (ctx->family != 2) {
        return SYS_PROCEED;
    }
    bpf_printk("connect: %pI4:%d", ctx->user_ip4, __bpf_ntohs(ctx->user_port));
    // bpf_printk("%pI4", ctx->msg_src_ip4);
    return SYS_PROCEED;
}

char __license[] SEC("license") = "GPL";
