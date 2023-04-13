package main

import (
	"fmt"
	"go-ebpf-demo/cilium-maglev/loadbalancer"
	"runtime"
	"sort"
)

func GetLookupTable(backendsMap map[string]*loadbalancer.Backend, m uint64) []int {
	if len(backendsMap) == 0 {
		return nil
	}

	backends := make([]string, 0, len(backendsMap))
	weightCntr := make(map[string]float64, len(backendsMap))
	weightSum := uint64(0)

	l := len(backendsMap)

	for name, b := range backendsMap {
		backends = append(backends, name)
		weightSum += uint64(b.Weight)
		weightCntr[name] = float64(b.Weight) / float64(l)
	}

	sort.Strings(backends)

	perm := getPermutation(backends, m, runtime.NumCPU())
	next := make([]int, len(backends))
	entry := make([]int, m)

	for j := uint64(0); j < m; j++ {
		entry[j] = -1
	}

	for n := uint64(0); n < m; n++ {
		i := int(n) % l
		for {
			// change the default selection of backend turns only if weights are used
			if weightSum/uint64(l) > 1 {
				if ((n + 1) * uint64(backendsMap[backends[i]].Weight)) < uint64(weightCntr[backends[i]]) {
					i = (i + 1) % l
					continue
				}
				weightCntr[backends[i]] += float64(weightSum)
			}
			c := perm[i*int(m)+next[i]]
			for entry[c] >= 0 {
				next[i] += 1
				c = perm[i*int(m)+next[i]]
			}
			entry[c] = int(backendsMap[backends[i]].ID)
			next[i] += 1
			break
		}
	}
	return entry
}

func main() {
	bk := map[string]*loadbalancer.Backend{
		"192.168.1.100": {
			FEPortName: "",
			ID:         100000100,
			Weight:     15,
			NodeName:   "100000100",
			// L3n4Addr:   loadbalancer.L3n4Addr{},
			State:     0,
			Preferred: false,
		},
		"192.168.1.200": {
			FEPortName: "",
			ID:         100000200,
			Weight:     10,
			NodeName:   "100000200",
			// L3n4Addr:   loadbalancer.L3n4Addr{},
			State:     0,
			Preferred: false,
		},
		"192.168.1.300": {
			FEPortName: "",
			ID:         100000300,
			Weight:     10,
			NodeName:   "100000300",
			// L3n4Addr:   loadbalancer.L3n4Addr{},
			State:     0,
			Preferred: false,
		},
	}

	tb := GetLookupTable(bk, 100)

	for _, v := range tb {
		fmt.Println(v)
	}
}
