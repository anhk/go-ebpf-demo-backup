
clsact 是用来给 TC + eBPF 是使用的一个 qdisc. 其parent固定为 ffff:fff1

在 ingress/egress 都提供了 hook

```bash
$ tc filter delete dev lo ingress
$ tc qdisc del dev lo clsact
```