package features

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/onsi/ginkgo/v2"

	"github.com/fatedier/frp/test/e2e/framework"
	"github.com/fatedier/frp/test/e2e/framework/consts"
	"github.com/fatedier/frp/test/e2e/pkg/request"
)

// writeFirewallState puts a frps_firewall.json where the spec's frps looks for
// it: the directory it runs from.
func writeFirewallState(f *framework.Framework, state map[string]any) {
	b, err := json.Marshal(state)
	framework.ExpectNoError(err)
	framework.ExpectNoError(os.WriteFile(filepath.Join(f.TempDirectory, "frps_firewall.json"), b, 0o600))
}

var _ = ginkgo.Describe("[Feature: Firewall]", func() {
	f := framework.NewDefaultFramework()

	tcpProxy := func(name string, remotePort int) string {
		return fmt.Sprintf(`
		[[proxies]]
		name = "%s"
		type = "tcp"
		localPort = {{ .%s }}
		remotePort = %d
		`, name, framework.TCPEchoServerPort, remotePort)
	}

	ginkgo.It("a rule refuses the port it names and nothing else", func() {
		blocked, open := f.AllocPort(), f.AllocPort()
		writeFirewallState(f, map[string]any{
			"enabled": true, "default": "allow",
			"rules": []map[string]any{
				{"id": "e2e", "action": "deny", "cidr": "127.0.0.1", "port": fmt.Sprint(blocked)},
			},
			"provider": map[string]any{"mode": "off"},
		})
		clientConf := consts.DefaultClientConfig + tcpProxy("blocked", blocked) + tcpProxy("open", open)
		f.RunProcesses(consts.DefaultServerConfig, []string{clientConf})

		framework.NewRequestExpect(f).Port(blocked).ExpectError(true).Explain("denied by the rule").Ensure()
		framework.NewRequestExpect(f).Port(open).Explain("no rule names this port").Ensure()
	})

	// The production lockout: the control port protected, the provider
	// configured to fail closed, and the provider unreachable - as it is
	// whenever the client that publishes it is the one trying to log in. A
	// client must still get through, or the provider can never come back.
	ginkgo.It("clients log in while the reputation provider is unreachable", func() {
		allowed, unknown := f.AllocPort(), f.AllocPort()
		deadProvider := f.AllocPort() // nothing listens here
		writeFirewallState(f, map[string]any{
			"enabled": true, "controlPort": true, "default": "allow",
			"rules": []map[string]any{
				{"id": "e2e", "action": "allow", "cidr": "127.0.0.1", "port": fmt.Sprint(allowed)},
			},
			"provider": map[string]any{
				"mode": "frpcontrol", "frpControlURL": fmt.Sprintf("http://127.0.0.1:%d", deadProvider),
				"frpControlAPIKey": "k", "timeoutMs": 500, "failOpen": false,
			},
		})
		clientConf := consts.DefaultClientConfig + tcpProxy("allowed", allowed) + tcpProxy("unknown", unknown)
		f.RunProcesses(consts.DefaultServerConfig, []string{clientConf})

		// The proxy answering at all means frpc got through the control port,
		// which no rule covers and which therefore asked the dead provider.
		framework.NewRequestExpect(f).Port(allowed).Explain("frpc logged in; the rule admits the visitor").Ensure()

		// Proxies keep the configured policy: with failOpen off, an address the
		// provider could not answer for is refused. The lookup the login set off
		// has failed by now; give it a moment on a slow runner.
		time.Sleep(500 * time.Millisecond)
		framework.NewRequestExpect(f).Port(unknown).ExpectError(true).Explain("the provider is down and failOpen is off").Ensure()
	})

	ginkgo.It("the dashboard API reads and writes the rules", func() {
		dashboardPort := f.AllocPort()
		serverConf := consts.DefaultServerConfig + fmt.Sprintf(`
		webServer.addr = "127.0.0.1"
		webServer.port = %d
		webServer.user = "admin"
		webServer.password = "admin"
		`, dashboardPort)
		remotePort := f.AllocPort()
		f.RunProcesses(serverConf, []string{consts.DefaultClientConfig + tcpProxy("tcp", remotePort)})

		api := func(method, body string) func(r *request.Request) {
			return func(r *request.Request) {
				r.HTTP().Port(dashboardPort).HTTPParams(method, "", "/api/firewall", nil).HTTPAuth("admin", "admin")
				if body != "" {
					r.Body([]byte(body))
				}
			}
		}

		framework.NewRequestExpect(f).Port(remotePort).Explain("open before any rule").Ensure()

		deny := fmt.Sprintf(`{"enabled":true,"default":"allow","rules":[{"action":"deny","cidr":"127.0.0.1","port":"%d"}],"provider":{"mode":"off"}}`, remotePort)
		framework.NewRequestExpect(f).RequestModify(api("PUT", deny)).Ensure(framework.ExpectResponseCode(200))
		framework.NewRequestExpect(f).Port(remotePort).ExpectError(true).Explain("a saved rule applies at once").Ensure()

		framework.NewRequestExpect(f).RequestModify(api("GET", "")).Ensure(func(resp *request.Response) bool {
			var c struct {
				Rules []struct{ ID, CIDR string }
			}
			return resp.Code == 200 && json.Unmarshal(resp.Content, &c) == nil &&
				len(c.Rules) == 1 && c.Rules[0].ID != "" && c.Rules[0].CIDR == "127.0.0.1"
		})

		// A rule that would silently match nothing is refused, and the one in
		// force stays.
		bad := `{"enabled":true,"default":"allow","rules":[{"action":"deny","cidr":"127.0.0.1/99","port":"all"}]}`
		framework.NewRequestExpect(f).RequestModify(api("PUT", bad)).Ensure(framework.ExpectResponseCode(400))
		framework.NewRequestExpect(f).Port(remotePort).ExpectError(true).Explain("a rejected save changed nothing").Ensure()

		// Saved where frps runs, so it survives a restart.
		b, err := os.ReadFile(filepath.Join(f.TempDirectory, "frps_firewall.json"))
		framework.ExpectNoError(err)
		framework.ExpectContainSubstring(string(b), fmt.Sprint(remotePort))

		framework.NewRequestExpect(f).RequestModify(func(r *request.Request) {
			r.HTTP().Port(dashboardPort).HTTPPath("/api/firewall/provider").HTTPAuth("admin", "admin")
		}).Ensure(func(resp *request.Response) bool {
			var st struct{ State string }
			return resp.Code == 200 && json.Unmarshal(resp.Content, &st) == nil && st.State == "off"
		})
	})
})
