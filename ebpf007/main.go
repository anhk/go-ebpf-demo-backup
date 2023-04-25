package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime/debug"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/florianl/go-tc"
	helper "github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf ebpf.c -- -I ./inc

// setupDummyInterface installs a temporary dummy interface
// func setupDummyInterface(iface string) *rtnetlink.Conn {
// 	con, err := rtnetlink.Dial(nil)
// 	Throw(err)

// 	Throw(con.Link.New(&rtnetlink.LinkMessage{
// 		Family: unix.AF_UNSPEC,
// 		Type:   unix.ARPHRD_NETROM,
// 		Index:  0,
// 		Flags:  unix.IFF_UP,
// 		Change: unix.IFF_UP,
// 		Attributes: &rtnetlink.LinkAttributes{
// 			Name: iface,
// 			Info: &rtnetlink.LinkInfo{Kind: "dummy"},
// 		},
// 	}))
// 	return con
// }

func main() {

	Throw(rlimit.RemoveMemlock())

	objs := &ebpfObjects{}
	Throw(loadEbpfObjects(objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf/"},
	}))
	defer objs.Close()

	tcnl, err := tc.Open(&tc.Config{})
	Throw(err)
	defer tcnl.Close()

	// var rtnl *rtnetlink.Conn
	tcIface := "lo"
	// rtnl := setupDummyInterface(tcIface)

	devId, err := net.InterfaceByName(tcIface)
	Throw(err)
	// defer func() { rtnl.Link.Delete(uint32(devId.Index)) }()

	qdisc := tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devId.Index),
			Handle:  helper.BuildHandle(0xFFFF, 0x0000),
			Parent:  tc.HandleIngress,
		},
		tc.Attribute{Kind: "clsact"},
	}
	Throw(tcnl.Qdisc().Add(&qdisc))
	defer tcnl.Qdisc().Delete(&qdisc)

	info, _ := objs.IngressDrop.Info()
	filter := tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devId.Index),
			Handle:  0,
			Parent:  0xfffffff2,
			Info:    0x10300,
		},
		tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    ptrHelper[uint32](uint32(objs.IngressDrop.FD())),
				Name:  &info.Name,
				Flags: ptrHelper[uint32](0x1),
			},
		},
	}

	Throw(tcnl.Filter().Add(&filter))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	<-ctx.Done()

	tcnl.Filter().Delete(&filter)
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
