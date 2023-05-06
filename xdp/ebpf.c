#include <linux/bpf.h>
#include "../inc/bpf_helpers.h"
#include "../inc/common.h"
#include "../inc/bpf_endian.h"

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx){
    bpf_printk("iface: %d", ctx->ingress_ifindex);
    return XDP_PASS;
}


char __license[] SEC("license") = "GPL";
