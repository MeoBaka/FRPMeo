package port

import (
	"fmt"
	"net"
	"strconv"
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"
)

type Allocator struct {
	reserved sets.Set[int]
	used     sets.Set[int]
	mu       sync.Mutex
}

// NewAllocator return a port allocator for testing.
// Example: from: 10, to: 20, mod 4, index 1
// Reserved ports: 13, 17
func NewAllocator(from int, to int, mod int, index int) *Allocator {
	pa := &Allocator{
		reserved: sets.New[int](),
		used:     sets.New[int](),
	}

	for i := from; i <= to; i++ {
		if i%mod == index {
			pa.reserved.Insert(i)
		}
	}
	return pa
}

func (pa *Allocator) Get() int {
	return pa.GetByName("")
}

func (pa *Allocator) GetByName(portName string) int {
	var builder *nameBuilder
	if portName == "" {
		builder = &nameBuilder{}
	} else {
		var err error
		builder, err = unmarshalFromName(portName)
		if err != nil {
			fmt.Println(err, portName)
			return 0
		}
	}

	pa.mu.Lock()
	defer pa.mu.Unlock()

	for range 20 {
		port := pa.getByRange(builder.rangePortFrom, builder.rangePortTo)
		if port == 0 {
			return 0
		}

		if !free(port) {
			// Maybe not controlled by us, mark it used.
			pa.used.Insert(port)
			continue
		}

		pa.used.Insert(port)
		pa.reserved.Delete(port)
		return port
	}
	return 0
}

// free reports whether nothing holds the port, for either protocol, on either
// of the addresses tests bind: frp listens on the wildcard, the mock servers on
// the loopback.
//
// Both have to be checked. On Windows a wildcard bind does not conflict with a
// bind to a specific address unless SO_EXCLUSIVEADDRUSE was set, so probing
// 0.0.0.0 alone reports a port as free while a process from the previous spec
// still holds 127.0.0.1 on it - and the port is handed out to a server that
// then fails to start. On Linux the wildcard bind does conflict, so the second
// probe changes nothing there.
func free(port int) bool {
	for _, host := range []string{"0.0.0.0", "127.0.0.1"} {
		addr := net.JoinHostPort(host, strconv.Itoa(port))

		l, err := net.Listen("tcp", addr)
		if err != nil {
			return false
		}
		l.Close()

		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return false
		}
		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return false
		}
		udpConn.Close()
	}
	return true
}

func (pa *Allocator) getByRange(from, to int) int {
	if from <= 0 {
		port, _ := pa.reserved.PopAny()
		return port
	}

	// choose a random port between from - to
	ports := pa.reserved.UnsortedList()
	for _, port := range ports {
		if port >= from && port <= to {
			return port
		}
	}
	return 0
}

func (pa *Allocator) Release(port int) {
	if port <= 0 {
		return
	}

	pa.mu.Lock()
	defer pa.mu.Unlock()

	if pa.used.Has(port) {
		pa.used.Delete(port)
		pa.reserved.Insert(port)
	}
}
