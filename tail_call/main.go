package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf ebpf.c -- -I ./inc

const mapKey uint32 = 0

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := ebpfObjects{}
	if err := loadEbpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.OpenatBeforeTail, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kp.Close()

	// key := 1

	// err = objs.ebpfMaps.TailJmpMap.Put(uint32(key), objs.ebpfPrograms.SysEnterOpen)
	// if err != nil {
	// 	log.Fatal("put tail jmp map failed", err)
	// }

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
