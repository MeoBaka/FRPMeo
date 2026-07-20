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

package selfupdate

import (
	"archive/zip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// The versions this fork actually publishes: seven dot-separated numbers, a
// "v" on the tag, "-dev" after it, " [DEV]" on what the binary reports.
func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// The comparison a string compare gets wrong: "1.6.35" < "1.5.29"
		// lexically, because '6' loses to '5' only after '1.' matches and then
		// 6 > 5 - but "1.10" vs "1.9" is the real trap, and it is numeric.
		{"1.6.35.0.70.0.0", "1.5.29.0.70.0.0", 1},
		{"1.5.29.0.70.0.0", "1.6.35.0.70.0.0", -1},
		{"1.6.35.0.70.0.0", "1.6.35.0.70.0.0", 0},
		{"1.10.0.0.70.0.0", "1.9.0.0.70.0.0", 1},
		{"1.6.100.0.70.0.0", "1.6.99.0.70.0.0", 1},

		// The frp base moving forward counts as newer too.
		{"1.6.35.0.71.0.0", "1.6.35.0.70.0.0", 1},

		// Decoration must not change the ordering.
		{"v1.6.35.0.70.0.0-dev", "1.5.29.0.70.0.0 [DEV]", 1},
		{"1.6.35.0.70.0.0 [DEV]", "v1.6.35.0.70.0.0-dev", 0},

		// Missing trailing components are zero.
		{"1.6.35", "1.6.35.0.0.0.0", 0},
		{"1.6.36", "1.6.35.0.70.0.0", 1},

		// An unparsable version must never look like an upgrade.
		{"not-a-version", "1.6.35.0.70.0.0", -1},
		{"1.6.35.0.70.0.0", "not-a-version", 1},
		{"", "1.6.35.0.70.0.0", -1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestNewerThan(t *testing.T) {
	releases := []Release{
		{TagName: "v1.7.02.0.70.0.0-dev"},
		{TagName: "v1.6.35.0.70.0.0-dev"},
		{TagName: "v1.5.29.0.70.0.0-dev"},
	}
	got := NewerThan(releases, "1.6.35.0.70.0.0 [DEV]")
	if len(got) != 1 || got[0].TagName != "v1.7.02.0.70.0.0-dev" {
		t.Fatalf("only the newer release should be offered, got %+v", got)
	}
	// Running the newest already: nothing on offer, and no false positive from
	// the release that equals it.
	if got := NewerThan(releases, "1.7.02.0.70.0.0 [DEV]"); len(got) != 0 {
		t.Fatalf("nothing should be newer, got %+v", got)
	}
}

func TestAssetForPicksThisPlatform(t *testing.T) {
	r := Release{Assets: []Asset{
		{Name: "frp_1.6.35.0.70.0.0-dev_linux_amd64.zip"},
		{Name: "frp_1.6.35.0.70.0.0-dev_windows_amd64.zip"},
		{Name: "SHA256SUMS.txt"},
	}}
	a, ok := AssetFor(r, "windows", "amd64")
	if !ok || a.Name != "frp_1.6.35.0.70.0.0-dev_windows_amd64.zip" {
		t.Fatalf("windows/amd64 picked %q (ok=%v)", a.Name, ok)
	}
	a, ok = AssetFor(r, "linux", "amd64")
	if !ok || a.Name != "frp_1.6.35.0.70.0.0-dev_linux_amd64.zip" {
		t.Fatalf("linux/amd64 picked %q (ok=%v)", a.Name, ok)
	}
	// A platform with no build must say so rather than install the wrong one.
	if _, ok := AssetFor(r, "darwin", "arm64"); ok {
		t.Fatal("darwin/arm64 has no build and must not match")
	}
}

func TestParseChecksums(t *testing.T) {
	in := `679b57e6ee7ddba84ff58252f2a49e7e6dc295b9aa13bae0c6f32fd855ef5073  frp_1.6.35.0.70.0.0-dev_linux_amd64.zip
25f393139d23c99aacbeb032eaf79491df3c98fae732f8d26a8663a8b859868c  frp_1.6.35.0.70.0.0-dev_windows_amd64.zip

garbage line
short  file.zip
`
	got := ParseChecksums(in)
	if len(got) != 2 {
		t.Fatalf("want 2 entries, got %d: %v", len(got), got)
	}
	if got["frp_1.6.35.0.70.0.0-dev_linux_amd64.zip"] != "679b57e6ee7ddba84ff58252f2a49e7e6dc295b9aa13bae0c6f32fd855ef5073" {
		t.Fatalf("linux checksum mismatch: %v", got)
	}
	if _, ok := got["file.zip"]; ok {
		t.Fatal("a line whose hash is not 64 hex chars must be ignored, not half-trusted")
	}
}

// Drafts are visible to the repo owner through the API; installing one would
// ship something not yet published.
func TestFetchReleasesSkipsDrafts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[
		  {"tag_name":"v1.8.0.0.70.0.0-dev","draft":true,"prerelease":true},
		  {"tag_name":"v1.7.0.0.70.0.0-dev","draft":false,"prerelease":true},
		  {"tag_name":"v1.6.35.0.70.0.0-dev","draft":false,"prerelease":true}
		]`))
	}))
	defer srv.Close()

	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	got, err := FetchReleases(context.Background(), "owner/repo")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("draft should be dropped, got %d: %+v", len(got), got)
	}
	if got[0].TagName != "v1.7.0.0.70.0.0-dev" {
		t.Fatalf("newest non-draft should lead, got %q", got[0].TagName)
	}
	// Pre-releases must survive: every release this fork publishes is one, and
	// dropping them would mean never seeing an update at all.
	if !got[0].Prerelease {
		t.Fatal("test fixture lost the prerelease flag")
	}
}

func TestFetchReleasesReportsHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer srv.Close()

	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	if _, err := FetchReleases(context.Background(), "owner/repo"); err == nil {
		t.Fatal("a 404 must be an error, not an empty list that reads as up to date")
	}
}

func TestExtractBinary(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "rel.zip")
	writeZip(t, zipPath, map[string]string{
		"frp_1.6.35_windows_amd64/frpc.exe": "FRPC-BODY",
		"frp_1.6.35_windows_amd64/frps.exe": "FRPS-BODY",
		"frp_1.6.35_windows_amd64/LICENSE":  "license",
	})

	dst := filepath.Join(dir, "out.exe")
	if err := extractBinary(zipPath, "frps.exe", dst); err != nil {
		t.Fatalf("extract: %v", err)
	}
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	// Picking the wrong one of two similarly named binaries would install frpc
	// over frps, which starts and then does nothing useful.
	if string(b) != "FRPS-BODY" {
		t.Fatalf("extracted the wrong entry: %q", b)
	}

	if err := extractBinary(zipPath, "nope.exe", filepath.Join(dir, "x")); err == nil {
		t.Fatal("a missing binary must be an error")
	}
}

func writeZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}
