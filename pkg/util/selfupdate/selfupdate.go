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

// Package selfupdate finds newer fork releases on GitHub and installs them.
package selfupdate

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// DefaultRepo is the fork these binaries are built from.
const DefaultRepo = "MeoBaka/FRPMeo"

// apiBase is a variable so tests can point at a local server. Nothing else
// should change it.
var apiBase = "https://api.github.com"

const (
	checksumAsset   = "SHA256SUMS.txt"
	maxAssetBytes   = 200 << 20 // a release asset is ~30 MB; this is a sanity bound
	requestTimeout  = 30 * time.Second
	downloadTimeout = 10 * time.Minute
)

// Release is one published release, reduced to what an update needs.
type Release struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	HTMLURL     string    `json:"html_url"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []Asset   `json:"assets"`
}

// Asset is one file attached to a release.
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// Version is the release's version without the tag decoration, e.g.
// "1.6.35.0.70.0.0" for tag "v1.6.35.0.70.0.0-dev".
func (r Release) Version() string { return normalizeVersion(r.TagName) }

// FetchReleases lists a repository's releases, newest first.
//
// It reads /releases rather than /releases/latest on purpose: this fork
// publishes every build as a pre-release, and /releases/latest ignores those -
// it answers 404 here, which would read as "no update available" forever.
func FetchReleases(ctx context.Context, repo string) ([]Release, error) {
	if repo == "" {
		repo = DefaultRepo
	}
	url := fmt.Sprintf("%s/repos/%s/releases?per_page=30", apiBase, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "frp-selfupdate")

	resp, err := (&http.Client{Timeout: requestTimeout}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("query releases: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("query releases: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var all []Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&all); err != nil {
		return nil, fmt.Errorf("decode releases: %w", err)
	}
	out := make([]Release, 0, len(all))
	for _, r := range all {
		if !r.Draft {
			out = append(out, r)
		}
	}
	return out, nil
}

// NewerThan returns the releases newer than current, newest first.
func NewerThan(releases []Release, current string) []Release {
	out := make([]Release, 0, len(releases))
	for _, r := range releases {
		if Compare(r.Version(), current) > 0 {
			out = append(out, r)
		}
	}
	return out
}

// AssetFor picks the archive built for this platform, e.g.
// "frp_1.6.35.0.70.0.0-dev_windows_amd64.zip".
func AssetFor(r Release, goos, goarch string) (Asset, bool) {
	suffix := fmt.Sprintf("_%s_%s.zip", goos, goarch)
	for _, a := range r.Assets {
		if strings.HasSuffix(a.Name, suffix) {
			return a, true
		}
	}
	return Asset{}, false
}

// ChecksumAsset returns the release's checksum file.
func ChecksumAsset(r Release) (Asset, bool) {
	for _, a := range r.Assets {
		if a.Name == checksumAsset {
			return a, true
		}
	}
	return Asset{}, false
}

// Compare orders two versions of the form "1.6.35.0.70.0.0", returning -1, 0
// or 1. Components are compared numerically, so 1.6.35 sorts above 1.5.29 the
// way a reader expects and the way a plain string compare would not. Missing
// trailing components count as zero, and anything unparsable sorts lowest so a
// malformed version never masquerades as an upgrade.
func Compare(a, b string) int {
	av, bv := parseVersion(a), parseVersion(b)
	for i := 0; i < len(av) || i < len(bv); i++ {
		x, y := 0, 0
		if i < len(av) {
			x = av[i]
		}
		if i < len(bv) {
			y = bv[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// normalizeVersion strips the decoration around a version: the "v" of a tag,
// the "-dev" suffix, and the " [DEV]" that the running binary reports.
func normalizeVersion(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	return s
}

func parseVersion(s string) []int {
	s = normalizeVersion(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil // unparsable: sorts below everything
		}
		out = append(out, n)
	}
	return out
}

// Apply downloads the release archive, checks it against the release's
// SHA256SUMS, and replaces the running executable with binaryName from inside
// it. The previous executable is kept alongside with a ".old" suffix.
//
// The caller has to restart: a process cannot replace itself in place, and on
// Windows it cannot even overwrite its own image while running.
func Apply(ctx context.Context, r Release, binaryName string, progress func(string)) error {
	if progress == nil {
		progress = func(string) {}
	}
	asset, ok := AssetFor(r, runtime.GOOS, runtime.GOARCH)
	if !ok {
		return fmt.Errorf("release %s has no build for %s/%s", r.TagName, runtime.GOOS, runtime.GOARCH)
	}
	sumAsset, ok := ChecksumAsset(r)
	if !ok {
		// Refuse rather than install something unverified: this writes an
		// executable that will be run with whatever privileges frp holds.
		return fmt.Errorf("release %s has no %s, refusing to install unverified", r.TagName, checksumAsset)
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate running executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
		exePath = resolved
	}

	dir := filepath.Dir(exePath)
	tmp, err := os.MkdirTemp(dir, ".frp-update-*")
	if err != nil {
		// Staging next to the target keeps the final step a rename within one
		// filesystem, which /tmp could not promise.
		return fmt.Errorf("create staging dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	progress(fmt.Sprintf("downloading %s (%.1f MB)", asset.Name, float64(asset.Size)/1e6))
	zipPath := filepath.Join(tmp, asset.Name)
	if err := download(ctx, asset.BrowserDownloadURL, zipPath); err != nil {
		return err
	}

	progress("verifying sha256")
	sums, err := fetchChecksums(ctx, sumAsset.BrowserDownloadURL)
	if err != nil {
		return err
	}
	want, ok := sums[asset.Name]
	if !ok {
		return fmt.Errorf("%s does not list %s", checksumAsset, asset.Name)
	}
	got, err := sha256File(zipPath)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("checksum mismatch for %s:\n  want %s\n  got  %s", asset.Name, want, got)
	}

	progress("extracting " + binaryName)
	newExe := filepath.Join(tmp, binaryName)
	if err := extractBinary(zipPath, binaryName, newExe); err != nil {
		return err
	}

	// Sanity-check what we are about to install, so a truncated or wrong-arch
	// download is caught here rather than at the next start.
	if fi, err := os.Stat(newExe); err != nil || fi.Size() < 1<<20 {
		return fmt.Errorf("extracted %s looks wrong (%v)", binaryName, err)
	}

	backup := exePath + ".old"
	_ = os.Remove(backup)
	// Rename rather than overwrite: Windows will not let a running image be
	// written, but it will let it be moved aside.
	if err := os.Rename(exePath, backup); err != nil {
		return fmt.Errorf("move current executable aside: %w", err)
	}
	if err := os.Rename(newExe, exePath); err != nil {
		_ = os.Rename(backup, exePath) // put it back
		return fmt.Errorf("install new executable: %w", err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(exePath, 0o755)
	}
	progress(fmt.Sprintf("installed %s (previous kept at %s)", exePath, filepath.Base(backup)))
	return nil
}

func download(ctx context.Context, url, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "frp-selfupdate")
	resp, err := (&http.Client{Timeout: downloadTimeout}).Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: %s", url, resp.Status)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, io.LimitReader(resp.Body, maxAssetBytes)); err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	return f.Sync()
}

func fetchChecksums(ctx context.Context, url string) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "frp-selfupdate")
	resp, err := (&http.Client{Timeout: requestTimeout}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("download checksums: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download checksums: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return ParseChecksums(string(body)), nil
}

// ParseChecksums reads "<sha256>  <filename>" lines, the format sha256sum
// writes and this project's SHA256SUMS.txt uses.
func ParseChecksums(s string) map[string]string {
	out := map[string]string{}
	for line := range strings.SplitSeq(s, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 2 || len(fields[0]) != 64 {
			continue
		}
		out[strings.TrimPrefix(fields[1], "*")] = strings.ToLower(fields[0])
	}
	return out
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// extractBinary copies the named binary out of the release archive. The archive
// holds one top-level directory, so the name is matched on the base rather than
// the full path.
func extractBinary(zipPath, binaryName, dst string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer zr.Close()

	for _, f := range zr.File {
		if filepath.Base(f.Name) != binaryName {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()

		out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		defer out.Close()
		if _, err := io.Copy(out, io.LimitReader(rc, maxAssetBytes)); err != nil {
			return err
		}
		return out.Sync()
	}
	return fmt.Errorf("archive does not contain %s", binaryName)
}
