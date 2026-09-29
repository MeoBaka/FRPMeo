package features

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/onsi/ginkgo/v2"

	"github.com/fatedier/frp/test/e2e/framework"
	"github.com/fatedier/frp/test/e2e/framework/consts"
	"github.com/fatedier/frp/test/e2e/pkg/request"
	"github.com/fatedier/frp/test/e2e/pkg/rpc"
)

const (
	secureTitle = "dangnhap"
	secureKey   = "e2e-secret-key"
)

// secureProxy is a proxy block with secure access on, plus extra settings.
func secureProxy(block string, extra string) string {
	return block + fmt.Sprintf(`
		secure.enable = true
		secure.title = "%s"
		secure.key = "%s"
		%s
		`, secureTitle, secureKey, extra)
}

func unlockLink(key string) func(r *request.Request) {
	return func(r *request.Request) {
		r.HTTP().HTTPPath("/?" + secureTitle + "=" + key)
	}
}

var _ = ginkgo.Describe("[Feature: Secure Access]", func() {
	f := framework.NewDefaultFramework()

	tcpProxy := func(remotePort int) string {
		return fmt.Sprintf(`
		[[proxies]]
		name = "tcp"
		type = "tcp"
		localPort = {{ .%s }}
		remotePort = %d
		`, framework.TCPEchoServerPort, remotePort)
	}

	udpProxy := func(remotePort int) string {
		return fmt.Sprintf(`
		[[proxies]]
		name = "udp"
		type = "udp"
		localPort = {{ .%s }}
		remotePort = %d
		`, framework.UDPEchoServerPort, remotePort)
	}

	ginkgo.It("TCP: refused until a link unlocks the address", func() {
		remotePort := f.AllocPort()
		clientConf := consts.DefaultClientConfig + secureProxy(tcpProxy(remotePort), "")
		f.RunProcesses(consts.DefaultServerConfig, []string{clientConf})

		framework.NewRequestExpect(f).Port(remotePort).ExpectError(true).Explain("no key yet").Ensure()

		framework.NewRequestExpect(f).Port(remotePort).RequestModify(unlockLink("wrong-key")).
			Ensure(framework.ExpectResponseCode(403))
		framework.NewRequestExpect(f).Port(remotePort).ExpectError(true).Explain("a wrong key unlocks nothing").Ensure()

		framework.NewRequestExpect(f).Port(remotePort).RequestModify(unlockLink(secureKey)).
			Ensure(framework.ExpectResponseCode(200))
		framework.NewRequestExpect(f).Port(remotePort).Explain("unlocked").Ensure()
	})

	ginkgo.It("TCP: a key line lets its connection through", func() {
		remotePort := f.AllocPort()
		clientConf := consts.DefaultClientConfig + secureProxy(tcpProxy(remotePort), "")
		f.RunProcesses(consts.DefaultServerConfig, []string{clientConf})

		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(remotePort)), 5*time.Second)
		framework.ExpectNoError(err)
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		_, err = conn.Write([]byte(secureTitle + ": " + secureKey + "\n"))
		framework.ExpectNoError(err)
		_, err = rpc.WriteBytes(conn, []byte(consts.TestString))
		framework.ExpectNoError(err)
		resp, err := rpc.ReadBytes(conn)
		framework.ExpectNoError(err)
		framework.ExpectEqualValues(string(resp), consts.TestString, "the echo server got the data, not the key line")

		framework.NewRequestExpect(f).Port(remotePort).ExpectError(true).
			Explain("a line admits its connection, not the address").Ensure()
	})

	ginkgo.It("TCP: trusted addresses need no key", func() {
		remotePort := f.AllocPort()
		clientConf := consts.DefaultClientConfig + secureProxy(tcpProxy(remotePort), `secure.trustedIPs = ["127.0.0.1"]`)
		f.RunProcesses(consts.DefaultServerConfig, []string{clientConf})

		framework.NewRequestExpect(f).Port(remotePort).Ensure()
	})

	ginkgo.It("TCP: outside the allow list even the key is refused", func() {
		remotePort := f.AllocPort()
		clientConf := consts.DefaultClientConfig + secureProxy(tcpProxy(remotePort), `secure.allowIPs = ["192.0.2.0/24"]`)
		f.RunProcesses(consts.DefaultServerConfig, []string{clientConf})

		framework.NewRequestExpect(f).Port(remotePort).RequestModify(unlockLink(secureKey)).ExpectError(true).Ensure()
		framework.NewRequestExpect(f).Port(remotePort).ExpectError(true).Ensure()
	})

	ginkgo.It("TCP: repeated wrong keys ban the address", func() {
		remotePort := f.AllocPort()
		clientConf := consts.DefaultClientConfig + secureProxy(tcpProxy(remotePort), `secure.antiSpam.maxFailures = 2`)
		f.RunProcesses(consts.DefaultServerConfig, []string{clientConf})

		for range 2 {
			framework.NewRequestExpect(f).Port(remotePort).RequestModify(unlockLink("wrong-key")).
				Ensure(framework.ExpectResponseCode(403))
		}
		framework.NewRequestExpect(f).Port(remotePort).RequestModify(unlockLink(secureKey)).ExpectError(true).
			Explain("banned: even the right key is turned away").Ensure()
	})

	ginkgo.It("HTTP: a header key, or a link that unlocks", func() {
		vhostHTTPPort := f.AllocPort()
		serverConf := consts.DefaultServerConfig + fmt.Sprintf(`
		vhostHTTPPort = %d
		`, vhostHTTPPort)
		clientConf := consts.DefaultClientConfig + secureProxy(fmt.Sprintf(`
		[[proxies]]
		name = "web"
		type = "http"
		localPort = {{ .%s }}
		customDomains = ["secure.example.com"]
		`, framework.HTTPSimpleServerPort), "")
		f.RunProcesses(serverConf, []string{clientConf})

		host := func(r *request.Request) *request.Request {
			return r.HTTP().HTTPHost("secure.example.com")
		}

		framework.NewRequestExpect(f).Port(vhostHTTPPort).
			RequestModify(func(r *request.Request) { host(r) }).
			Ensure(framework.ExpectResponseCode(401))

		framework.NewRequestExpect(f).Port(vhostHTTPPort).
			RequestModify(func(r *request.Request) {
				host(r).HTTPHeaders(map[string]string{secureTitle: "wrong-key"})
			}).
			Ensure(framework.ExpectResponseCode(403))

		framework.NewRequestExpect(f).Port(vhostHTTPPort).
			RequestModify(func(r *request.Request) {
				host(r).HTTPHeaders(map[string]string{secureTitle: secureKey})
			}).
			Explain("a header key proves each request").Ensure()

		// The link answers with a redirect to the same page without the key,
		// which the client follows as an unlocked address.
		framework.NewRequestExpect(f).Port(vhostHTTPPort).
			RequestModify(func(r *request.Request) {
				host(r).HTTPPath("/?" + secureTitle + "=" + secureKey)
			}).
			Explain("the link unlocks and redirects").Ensure()

		framework.NewRequestExpect(f).Port(vhostHTTPPort).
			RequestModify(func(r *request.Request) { host(r) }).
			Explain("unlocked").Ensure()
	})

	ginkgo.It("UDP: dropped until a link on the same port unlocks the address", func() {
		remotePort := f.AllocPort()
		clientConf := consts.DefaultClientConfig + secureProxy(udpProxy(remotePort), "")
		f.RunProcesses(consts.DefaultServerConfig, []string{clientConf})

		framework.NewRequestExpect(f).Protocol("udp").Port(remotePort).ExpectError(true).
			Explain("no key yet").Ensure()

		// frps answers the link over tcp on the udp proxy's port number.
		framework.NewRequestExpect(f).Port(remotePort).RequestModify(unlockLink(secureKey)).
			Ensure(framework.ExpectResponseCode(200))

		framework.NewRequestExpect(f).Protocol("udp").Port(remotePort).Explain("unlocked").Ensure()
	})

	ginkgo.It("UDP: a key datagram unlocks its source", func() {
		remotePort := f.AllocPort()
		clientConf := consts.DefaultClientConfig + secureProxy(udpProxy(remotePort), `secure.methods = ["line"]`)
		f.RunProcesses(consts.DefaultServerConfig, []string{clientConf})

		framework.NewRequestExpect(f).Protocol("udp").Port(remotePort).ExpectError(true).
			Explain("no key yet").Ensure()

		conn, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(remotePort)))
		framework.ExpectNoError(err)
		_, err = conn.Write([]byte(secureTitle + ": " + secureKey))
		framework.ExpectNoError(err)
		_ = conn.Close()

		framework.NewRequestExpect(f).Protocol("udp").Port(remotePort).Explain("unlocked").Ensure()
	})
})
