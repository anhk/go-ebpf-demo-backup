package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf ebpf.c -- -I ./inc

func main() {
	// FIXME: check cgroups

	cg := flag.String("cgroup2", "/sys/fs/cgroup", "cgroup2 path")
	flag.Parse()

	Throw(rlimit.RemoveMemlock())

	objs := &ebpfObjects{}
	Throw(loadEbpfObjects(objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf/"},
	}))
	defer objs.Close()

	fmt.Println("cgroup2 path: ", *cg)
	// attach cgroup
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    *cg,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.SockConnect4,
	})
	Throw(err)
	defer l.Close()

	// pin
	if err := l.Pin(fmt.Sprintf("/sys/fs/bpf/connect4")); err != nil {
		fmt.Println("pin failed:", err)
	}

	// print debug info
	f, err := os.OpenFile("/sys/kernel/debug/tracing/trace_pipe", os.O_RDONLY, os.ModePerm)
	Throw(err)
	defer f.Close()

	reader := bufio.NewReader(f)
	for {
		line, _, err := reader.ReadLine()
		if err == io.EOF {
			break
		}
		fmt.Println(string(line))
	}
}

func Throw(e any) {
	if e != nil {
		fmt.Printf("%s\n", e)
		fmt.Printf("%s\n", debug.Stack())
		os.Exit(-1)
	}
}
