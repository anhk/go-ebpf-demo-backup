package main

import (
	"fmt"
	"go-ebpf-demo/checkmount/mountinfo"
	"os"

	"golang.org/x/sys/unix"
)

type MountPoint struct {
	MountPoint         string
	FallbackMountPoint string
	FilesystemType     string
}

// 支持CGroup2 & BPF
func Mount(mountPoint MountPoint) (string, error) {
	var mntType int64
	switch mountPoint.FilesystemType {
	case "bpf":
		mntType = mountinfo.FilesystemTypeBPFFS
	case "cgroup2":
		mntType = mountinfo.FilesystemTypeCgroup2
	default:
		return "", fmt.Errorf("not support filesystem type: %v", mountPoint.FilesystemType)
	}

	_, ok, err := mountinfo.IsMountFS(mntType, mountPoint.MountPoint)
	if err != nil {
		return "", fmt.Errorf("check mountPoint [%v]: %v", mountPoint.MountPoint, err)
	} else if ok {
		return mountPoint.MountPoint, nil
	}

	if _, ok, err := mountinfo.IsMountFS(mntType, mountPoint.FallbackMountPoint); err != nil {
		return "", fmt.Errorf("check mountPoint [%v]: %v", mountPoint.FallbackMountPoint, err)
	} else if ok {
		return mountPoint.FallbackMountPoint, nil
	}
	os.MkdirAll(mountPoint.FallbackMountPoint, 0700)

	return mountPoint.FallbackMountPoint, unix.Mount(mountPoint.FilesystemType,
		mountPoint.FallbackMountPoint, mountPoint.FilesystemType, 0, "")
}
