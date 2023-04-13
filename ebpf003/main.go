package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"runtime/debug"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf ebpf.c -- -I ./inc

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	objs := &ebpfObjects{}
	if err := loadEbpfObjects(objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf/"},
	}); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// register `kprobe` hook
	kp, err := link.Kprobe("sys_execve", objs.BpfProg, nil)
	Throw(err)
	defer kp.Close()

	// run test ebpf map
	go runTestEbpf(objs)

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

func Throw(e any) {
	if e != nil {
		fmt.Printf("%s\n", e)
		fmt.Printf("%s\n", debug.Stack())
		panic(e)
	}
}

func runTestEbpf(objs *ebpfObjects) {
	fmt.Println(objs.M4.MaxEntries())
	fmt.Println(objs.M4.String())

	for i := uint32(0); i < objs.M4.MaxEntries(); i++ {
		objs.M4.Update(i, i+203, ebpf.UpdateAny)
	}

	var k, v uint32
	for iter := objs.M4.Iterate(); iter.Next(&k, &v); {
		fmt.Println(k, v)
	}
}
