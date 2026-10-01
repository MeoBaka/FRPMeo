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
// actually asks: the decision, then the report.

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

// A source the provider has already answered for: the common case once a
// server has been up for a while, and the one every connection pays.
func BenchmarkAllowWithCachedProviderAnswer(b *testing.B) {
	f := benchFirewall(b, Config{
		Enabled: true, Default: "allow", Rules: rules(8),
		Provider: ProviderConfig{Mode: "off"},
	})
	f.mu.Lock()
	f.query = ProviderConfig{Mode: "custom", URL: "http://provider.invalid/{ip}", BlockedPath: "blocked"}
	f.mu.Unlock()
	f.repMu.Lock()
	f.repCache["203.0.113.7"] = repEntry{answered: true, fresh: 1 << 62, next: 1 << 62}
	f.repMu.Unlock()

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if ok, _ := f.Allow("203.0.113.7:40000", 6000); !ok {
			b.Fatal("denied")
		}
	}
}

// Contention: the monitor and the cache are shared, so what one core measures
// is not what eight cores get.
func BenchmarkProxyConnParallel(b *testing.B) {
	f := benchFirewall(b, Config{
		Enabled: true, Default: "allow", Rules: rules(8),
		Provider: ProviderConfig{Mode: "off"},
	})

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			addr := fmt.Sprintf("203.0.%d.%d:40000", i/256%256, i%256)
			i++
			ok, reason := f.Allow(addr, 6000)
			f.NoteDecision(SurfaceProxy, ok, reason, addr)
		}
	})
}
