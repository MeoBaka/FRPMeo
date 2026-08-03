// Copyright 2026 The frp Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package firewall

import (
	"fmt"
	"path/filepath"
	"testing"
)

// What one connection costs this package, measured the way a connection
// actually asks: the rules, then the rate limit, then the report.
//
// The number that matters is not any one of these on its own but the gap
// between the disabled case and the full one, because that gap is what turning
// the firewall on adds to every connection frps accepts.

func benchFirewall(b *testing.B, cfg Config) *Firewall {
	b.Helper()
	f, err := New(filepath.Join(b.TempDir(), "fw.json"))
	if err != nil {
		b.Fatalf("new firewall: %v", err)
	}
	if err := f.SetConfig(cfg); err != nil {
		b.Fatalf("set config: %v", err)
	}
	return f
}

func rules(n int) []Rule {
	out := make([]Rule, 0, n)
	for i := range n {
		out = append(out, Rule{
			ID:     fmt.Sprintf("r%d", i),
			Action: "deny",
			CIDR:   fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
			Port:   "all",
		})
	}
	return out
}

func fullAntiAttacker() AntiAttackerConfig {
	return AntiAttackerConfig{
		Enabled: true,
		TCP: RateProfile{
			Enabled: true, WindowMs: 1000, MaxPerWindow: 1_000_000_000,
			BanViolations: 99, IdleForgetMs: 60000, MaxTracked: 65536,
			SubnetMaxPerWindow: 1_000_000_000, GlobalMaxPerWindow: 1_000_000_000,
		},
		Control: ControlProfile{Protect: true, RateProfile: RateProfile{
			Enabled: true, WindowMs: 1000, MaxPerWindow: 1_000_000_000,
			BanViolations: 99, IdleForgetMs: 60000, MaxTracked: 65536,
		}},
		Attack:  AttackConfig{Enabled: true, ConnectionsPerSec: 1_000_000_000, CooldownSec: 10},
		Trust:   TrustConfig{Enabled: true, AfterMs: 300000, MinBytes: 4096, ForSeconds: 86400, MaxTracked: 65536},
		Strikes: StrikeConfig{Enabled: true, ProtocolFailures: 3, EmptyConnections: 5, BanSeconds: 60, ForgetMs: 300000, MaxTracked: 65536},
	}
}

// Off: what a connection costs when the firewall is disabled, which is the
// baseline every other number here should be read against.
func BenchmarkProxyConnDisabled(b *testing.B) {
	f := benchFirewall(b, Config{Enabled: false, Default: "allow", Provider: ProviderConfig{Mode: "off"}})
	benchProxyConn(b, f)
}

// Rules only, which is what the firewall was before any of this work.
func BenchmarkProxyConnRulesOnly(b *testing.B) {
	f := benchFirewall(b, Config{
		Enabled: true, Default: "allow", Rules: rules(8),
		Provider: ProviderConfig{Mode: "off"},
	})
	benchProxyConn(b, f)
}

// Everything on: rules, all three rate tiers, trust, strikes, attack state and
// the per-surface report.
func BenchmarkProxyConnFull(b *testing.B) {
	f := benchFirewall(b, Config{
		Enabled: true, Default: "allow", Rules: rules(8),
		Provider: ProviderConfig{Mode: "off"}, AntiAttacker: fullAntiAttacker(),
	})
	benchProxyConn(b, f)
}

// One user connection to a proxy port, in the order server/proxy asks.
func benchProxyConn(b *testing.B, f *Firewall) {
	const addr = "203.0.113.7:40000"
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		ok, reason := f.Allow(addr, 6000)
		if !ok {
			b.Fatalf("benchmark address was denied: %s", reason)
		}
		if v := f.AdmitTCP(addr); !v.Allowed {
			b.Fatalf("benchmark address was rate limited: %s", v.Reason)
		}
		_, release := f.AcquireConn(addr)
		f.NoteDecision(SurfaceProxy, true, reason, addr)
		release()
	}
}

// The control port, which is the path an frpc login walks.
func BenchmarkControlConnFull(b *testing.B) {
	f := benchFirewall(b, Config{
		Enabled: true, ControlPort: true, Default: "allow", Rules: rules(8),
		Provider: ProviderConfig{Mode: "off"}, AntiAttacker: fullAntiAttacker(),
	})

	const addr = "203.0.113.7:40000"
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		ok, reason := f.AllowControl(addr, 7000)
		if !ok {
			b.Fatalf("denied: %s", reason)
		}
		if v := f.AdmitControl(addr); !v.Allowed {
			b.Fatalf("rate limited: %s", v.Reason)
		}
		f.NoteDecision(SurfaceControl, true, reason, addr)
	}
}

// Rule matching is a linear scan, so this is where a big imported blocklist
// would show up. Run it before pasting one in.
func BenchmarkAllowByRuleCount(b *testing.B) {
	for _, n := range []int{0, 8, 64, 512, 4096} {
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			f := benchFirewall(b, Config{
				Enabled: true, Default: "allow", Rules: rules(n),
				Provider: ProviderConfig{Mode: "off"},
			})
			b.ReportAllocs()
			b.ResetTimer()

			// 203.0.113.7 matches none of them, so every rule is examined -
			// the worst case, and the one an allow-by-default setup hits on
			// every connection.
			for range b.N {
				if ok, _ := f.Allow("203.0.113.7:40000", 6000); !ok {
					b.Fatal("denied")
				}
			}
		})
	}
}

// Contention: the counters are shared, so what one core measures is not what
// eight cores get.
func BenchmarkProxyConnFullParallel(b *testing.B) {
	f := benchFirewall(b, Config{
		Enabled: true, Default: "allow", Rules: rules(8),
		Provider: ProviderConfig{Mode: "off"}, AntiAttacker: fullAntiAttacker(),
	})

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			// Distinct sources, which is both the harder case for the tracker
			// map and what a real flood looks like.
			addr := fmt.Sprintf("203.0.%d.%d:40000", i/256%256, i%256)
			i++
			ok, reason := f.Allow(addr, 6000)
			f.AdmitTCP(addr)
			f.NoteDecision(SurfaceProxy, ok, reason, addr)
		}
	})
}
