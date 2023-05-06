package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/debug"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf ebpf.c -- -I ./inc

func main() {

	Throw(rlimit.RemoveMemlock())

	objs := &ebpfObjects{}
	Throw(loadEbpfObjects(objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf/"},
	}))
	defer objs.Close()
	ifce, err := net.InterfaceByName("enp0s1")
	Throw(err)

	xdp, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: ifce.Index,
	})
	Throw(err)
	defer xdp.Close()
	// print debug info
	f, _ := os.OpenFile("/sys/kernel/debug/tracing/trace_pipe", os.O_RDONLY, os.ModePerm)
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

func ptrHelper[T any](v T) *T {
	return &v
}

func Throw(e any) {
	if e != nil {
		fmt.Printf("%s\n", e)
		fmt.Printf("%s\n", debug.Stack())
		os.Exit(-1)
	}
}
