#include <linux/bpf.h>
#include "../inc/bpf_helpers.h"
#include "../inc/common.h"
#include "../inc/bpf_endian.h"

#define TC_ACT_UNSPEC (-1)  // Uses standard TC action
#define TC_ACT_OK 0         // Delivers the packet in the TC queue
#define TC_ACT_RECLASSIFY 1 // Restarts the classification from the beginning
#define TC_ACT_SHOT 2       // Drop Packet
#define TC_ACT_PIPE 3       // Iterate to the next action, if available
#define TC_ACT_STOLEN 4
#define TC_ACT_QUEUED 5
#define TC_ACT_REPEAT 6
#define TC_ACT_REDIRECT 7
#define TC_ACT_TRAP 8

SEC("classifier/ingress/drop001")
int ingress_drop_1(struct __sk_buff *skb)
{
    bpf_printk("ingress_drop001");
    return TC_ACT_OK;
}

SEC("classifier/ingress/drop002")
int ingress_drop_2(struct __sk_buff *skb)
{
    bpf_printk("ingress_drop002");
    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
