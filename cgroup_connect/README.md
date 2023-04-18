# cgroup connect

```bash
# check
$ cat /proc/mounts  | grep -w ^cgroup2

# set
$ mkdir -p /sys/fs/cgroup/
$ mount -t cgroup2 none /sys/fs/cgroup/

# check
$ bpftool cgroup tree
```
