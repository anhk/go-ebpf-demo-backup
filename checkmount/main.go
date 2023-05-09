package main

import (
	"fmt"
	"os"
	"runtime/debug"
)

const (
	defaultPinPath    = "/sys/fs/bpf"
	defaultCgroupPath = "/sys/fs/cgroup"

	fallbackPinPath    = "/run/kubelink/bpffs"
	fallbackCgroupPath = "/run/kubelink/cgroup2"
)

func main() {
	fmt.Println(Mount(MountPoint{
		MountPoint:         defaultPinPath,
		FallbackMountPoint: fallbackPinPath,
		FilesystemType:     "bpf",
	}))

	fmt.Println(Mount(MountPoint{
		MountPoint:         defaultCgroupPath,
		FallbackMountPoint: fallbackCgroupPath,
		FilesystemType:     "cgroup2",
	}))
}

func Throw(e any) {
	if e != nil {
		fmt.Printf("%s\n", e)
		fmt.Printf("%s\n", debug.Stack())
		os.Exit(-1)
	}
}
