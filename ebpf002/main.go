package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"runtime/debug"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
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

	go runTestEbpf(objs)

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

	for i := 0; i < 10; i++ {
		m, err := ebpf.NewMap(&ebpf.MapSpec{
			Name:       "default.inner_map_001",
			Type:       ebpf.Hash,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 4096,
			Flags:      unix.BPF_F_NO_PREALLOC,
		})
		Throw(err)

		fmt.Println("create map ok.")

		Throw(objs.M4.Update(uint32(i), m, ebpf.UpdateAny))
	}

	var k uint32
	var mapId ebpf.MapID
	for iter := objs.M4.Iterate(); iter.Next(&k, &mapId); {
		fmt.Println("k:", k, "mapId:", mapId)
		innerMap, err := ebpf.NewMapFromID(mapId)
		Throw(err)

		fmt.Println(innerMap.Info())
	}
}
