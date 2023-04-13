package loadbalancer

import "go-ebpf-demo/cilium-maglev/cmtypes"

type BackendID uint32
type L4Type = string
type BackendState uint8
type Preferred bool

type L4Addr struct {
	Protocol L4Type
	Port     uint16
}

type L3n4Addr struct {
	AddrCluster cmtypes.AddrCluster
	L4Addr
	Scope uint8
}

type Backend struct {
	// FEPortName is the frontend port name. This is used to filter backends sending to EDS.
	FEPortName string
	// ID of the backend
	ID BackendID
	// Weight of backend
	Weight uint16
	// Node hosting this backend. This is used to determine backends local to
	// a node.
	NodeName string
	L3n4Addr
	// State of the backend for load-balancing service traffic
	State BackendState
	// Preferred indicates if the healthy backend is preferred
	Preferred Preferred
}
