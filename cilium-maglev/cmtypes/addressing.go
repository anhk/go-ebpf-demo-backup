package cmtypes

import "net/netip"

type AddrCluster struct {
	addr      netip.Addr
	clusterID uint32
}
