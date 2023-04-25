#include <linux/bpf.h>
#include "../inc/bpf_helpers.h"
#include "../inc/common.h"
#include "../inc/bpf_endian.h"

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_REDIRECT 7

SEC("classifier_ingress_drop")
int ingress_drop(struct __sk_buff *skb)
{
    bpf_printk("ingress_drop002");
    return TC_ACT_OK;
}

SEC("classifier_egress_drop")
int egress_drop(struct __sk_buff *skb)
{
    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
