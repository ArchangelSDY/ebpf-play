package main

import (
	"flag"
	"log"
	"net"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	// "github.com/cilium/ebpf/link"
)

// func main() {
// 	var ifName string
// 	flag.StringVar(&ifName, "if", "", "Interface name")
// 	flag.Parse()
//
// 	var objs tunnelObjects
// 	if err := loadTunnelObjects(&objs, nil); err != nil {
// 		log.Fatal("Loading eBPF objects:", err)
// 	}
// 	defer objs.Close()
//
// 	iface, err := net.InterfaceByName(ifName)
// 	if err != nil {
// 		log.Fatalf("Getting interface %s: %s", ifName, err)
// 	}
//
// 	link, err := link.AttachTC(link.TCOptions{
// 		Program:   objs.SetTunnelRemote,
// 		Interface: iface.Index,
// 	})
// 	if err != nil {
// 		log.Fatalf("Attaching TC", err)
// 	}
// 	defer link.Close()
//
// 	// TODO: Set map
//
// }

func main() {
	var ifName string
	flag.StringVar(&ifName, "if", "", "Interface name")
	flag.Parse()

	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifName, err)
	}

	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		log.Fatalf("Cannot open rtnetlink socket: %s", err)
	}
	defer tcnl.Close()

	if err = tcnl.SetOption(netlink.ExtendedAcknowledge, true); err != nil {
		log.Fatalf("Cannot set option ExtendedAcknowledge: %s", err)
	}

	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
			// TODO
			Parent: tc.HandleIngress,
			Info:   0,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}
	if err = tcnl.Qdisc().Add(&qdisc); err != nil {
		log.Fatalf("Cannot assign clsact: %s", err)
	}

	// spec := ebpf.ProgramSpec

}
