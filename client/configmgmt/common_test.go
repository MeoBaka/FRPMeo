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

package configmgmt

import (
	"slices"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

const sample = `
serverAddr = "1.2.3.4"
serverPort = 7000

[auth]
token = "sekrit"

[transport]
protocol = "tcp"
poolCount = 5

[[proxies]]
name = "web"
type = "tcp"
localPort = 80
remotePort = 8080

[[proxies]]
name = "ssh"
type = "tcp"
localPort = 22
remotePort = 2222

[[visitors]]
name = "v1"
type = "stcp"
serverName = "other"
secretKey = "k"
bindPort = 9000
`

func mustRead(t *testing.T, content string) *v1.ClientCommonConfig {
	t.Helper()
	cfg, err := ReadCommonConfig(content)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return cfg
}

func TestReadCommonConfig(t *testing.T) {
	cfg := mustRead(t, sample)

	if cfg.ServerAddr != "1.2.3.4" || cfg.ServerPort != 7000 {
		t.Fatalf("server = %s:%d, want 1.2.3.4:7000", cfg.ServerAddr, cfg.ServerPort)
	}
	if cfg.Auth.Token != "sekrit" {
		t.Fatalf("token = %q", cfg.Auth.Token)
	}
	if cfg.Transport.Protocol != "tcp" || cfg.Transport.PoolCount != 5 {
		t.Fatalf("transport = %+v", cfg.Transport)
	}
}

// The thing that must not break: editing a client setting cannot cost somebody
// their proxies.
func TestMergeKeepsProxiesAndVisitors(t *testing.T) {
	cfg := mustRead(t, sample)
	cfg.Transport.Protocol = "wss"

	out, err := MergeCommonConfig(sample, cfg)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}

	var got struct {
		Proxies  []map[string]any `toml:"proxies"`
		Visitors []map[string]any `toml:"visitors"`
	}
	if err := toml.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("result is not valid toml: %v", err)
	}
	if len(got.Proxies) != 2 {
		t.Fatalf("%d proxies survived, want 2", len(got.Proxies))
	}
	if got.Proxies[0]["name"] != "web" || got.Proxies[1]["name"] != "ssh" {
		t.Fatalf("proxies came back changed: %+v", got.Proxies)
	}
	if len(got.Visitors) != 1 || got.Visitors[0]["name"] != "v1" {
		t.Fatalf("visitors came back changed: %+v", got.Visitors)
	}
}

func TestMergeAppliesTheChange(t *testing.T) {
	cfg := mustRead(t, sample)
	cfg.Transport.Protocol = "wss"
	cfg.ServerPort = 443

	out, err := MergeCommonConfig(sample, cfg)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	after := mustRead(t, out)

	if after.Transport.Protocol != "wss" {
		t.Fatalf("protocol = %q, want wss", after.Transport.Protocol)
	}
	if after.ServerPort != 443 {
		t.Fatalf("serverPort = %d, want 443", after.ServerPort)
	}
	if after.Auth.Token != "sekrit" {
		t.Fatal("an untouched client setting was lost")
	}
}

// A key this build does not know about belongs to somebody - a newer frp, a
// hand-written extra - and rewriting the file must not be how they find out it
// is gone.
func TestMergeKeepsUnknownKeys(t *testing.T) {
	src := sample + "\n[somethingNew]\nkey = \"value\"\n"

	cfg := mustRead(t, src)
	cfg.ServerPort = 7001

	out, err := MergeCommonConfig(src, cfg)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if !strings.Contains(out, "somethingNew") || !strings.Contains(out, "value") {
		t.Fatalf("an unrecognized section was dropped:\n%s", out)
	}
}

// Clearing a field has to remove the key, not write a zero: a config that says
// serverPort = 0 is worse than one that says nothing.
func TestMergeRemovesClearedFields(t *testing.T) {
	cfg := mustRead(t, sample)
	cfg.Transport.PoolCount = 0

	out, err := MergeCommonConfig(sample, cfg)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if strings.Contains(out, "poolCount") {
		t.Fatalf("a cleared field was written as a zero:\n%s", out)
	}
}

func TestMergeRejectsBrokenExistingFile(t *testing.T) {
	cfg := &v1.ClientCommonConfig{ServerAddr: "1.2.3.4"}
	if _, err := MergeCommonConfig("this is not = toml [[[", cfg); err == nil {
		t.Fatal("a config file that does not parse was merged into anyway")
	}
}

func TestMergeIntoEmptyFile(t *testing.T) {
	cfg := &v1.ClientCommonConfig{ServerAddr: "9.9.9.9", ServerPort: 7000}

	out, err := MergeCommonConfig("", cfg)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	after := mustRead(t, out)
	if after.ServerAddr != "9.9.9.9" {
		t.Fatalf("serverAddr = %q", after.ServerAddr)
	}
}

func TestMergeRejectsNilConfig(t *testing.T) {
	if _, err := MergeCommonConfig(sample, nil); err == nil {
		t.Fatal("a nil config was accepted")
	}
}

// The key list is read off the struct so a field added later is covered without
// anyone remembering to update a list.
func TestCommonConfigKeysCoverTheStruct(t *testing.T) {
	keys := commonConfigKeys()
	for _, want := range []string{"serverAddr", "serverPort", "auth", "transport", "log", "webServer"} {
		if !contains(keys, want) {
			t.Errorf("%q is missing from the key list", want)
		}
	}
	// And nothing that belongs to the file rather than to this struct.
	for _, unwanted := range []string{"proxies", "visitors"} {
		if contains(keys, unwanted) {
			t.Errorf("%q is a file-level key and must not be rewritten", unwanted)
		}
	}
}

func contains(s []string, v string) bool {
	return slices.Contains(s, v)
}

func TestDecodeCommonConfig(t *testing.T) {
	cfg, err := DecodeCommonConfig([]byte(`{"common":{"serverAddr":"1.1.1.1","serverPort":7000}}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cfg.ServerAddr != "1.1.1.1" {
		t.Fatalf("serverAddr = %q", cfg.ServerAddr)
	}
	if _, err := DecodeCommonConfig([]byte(`{}`)); err == nil {
		t.Fatal("a body with no common config was accepted")
	}
}

// The json hop turns every number into a float, and a port written as 7000.0 is
// wrong to everything except the loader that took the same route.
func TestMergeWritesIntegersNotFloats(t *testing.T) {
	cfg := mustRead(t, sample)
	cfg.ServerPort = 7000

	out, err := MergeCommonConfig(sample, cfg)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if strings.Contains(out, ".0") {
		t.Fatalf("a number was written as a float:\n%s", out)
	}
	if !strings.Contains(out, "serverPort = 7000") {
		t.Fatalf("serverPort is not a plain integer:\n%s", out)
	}
}

// Structs without omitempty on their nested fields contribute an empty table
// each, so a small config grows a crop of headers that say nothing.
func TestMergeDropsEmptyTables(t *testing.T) {
	cfg := mustRead(t, sample)

	out, err := MergeCommonConfig(sample, cfg)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	for _, empty := range []string{"[auth.oidc]", "[transport.quic]", "[transport.tls]", "[virtualNet]", "[store]"} {
		if strings.Contains(out, empty) {
			t.Errorf("%s was written despite holding nothing:\n%s", empty, out)
		}
	}
}

// An empty list is a statement - "none" - and different from leaving the key
// out, so it survives.
func TestTidyKeepsEmptyLists(t *testing.T) {
	got := tidy(map[string]any{"list": []any{}, "table": map[string]any{}})
	m := got.(map[string]any)
	if _, ok := m["list"]; !ok {
		t.Error("an empty list was dropped")
	}
	if _, ok := m["table"]; ok {
		t.Error("an empty table was kept")
	}
}
