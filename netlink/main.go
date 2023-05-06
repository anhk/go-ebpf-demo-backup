package main

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/vishvananda/netlink"
)

func main() {
	link, err := netlink.LinkByName("docker0")
	Throw(err)

	fmt.Println(link.Attrs())
	fmt.Printf("%T\n", link)
	fmt.Println(netlink.FilterList(link, 0))
}

func Throw(e any) {
	if e != nil {
		fmt.Printf("%s\n", e)
		fmt.Printf("%s\n", debug.Stack())
		os.Exit(-1)
	}
}
