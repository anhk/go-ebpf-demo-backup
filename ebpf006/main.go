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
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "maglev",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4 * 32767,
		MaxEntries: 1,
		Contents:   []ebpf.MapKV{},
	})
	Throw(err)

	var arr [32767]uint32
	for i := range arr {
		arr[i] = uint32(i)
	}

	Throw(m.Update(uint32(0), arr, ebpf.UpdateAny))

	Throw(objs.MaglveMap4.Update(uint32(9), m, ebpf.UpdateAny))

}
