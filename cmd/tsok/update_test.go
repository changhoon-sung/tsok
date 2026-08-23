package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUpdateExecutableReplacesBinary(t *testing.T) {
	archive := testReleaseArchive(t, []byte("new tsok binary"))
	archiveHash := sha256.Sum256(archive)
	checksums := fmt.Sprintf("%s  tsok_linux_amd64.tar.gz\n", hex.EncodeToString(archiveHash[:]))

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/latest":
			_ = json.NewEncoder(writer).Encode(releaseInfo{
				TagName: "v0.2.0",
				Assets: []releaseAsset{
					{Name: "tsok_linux_amd64.tar.gz", URL: server.URL + "/archive"},
					{Name: "tsok_0.2.0_SHA256SUMS", URL: server.URL + "/checksums"},
				},
			})
		case "/archive":
			_, _ = writer.Write(archive)
		case "/checksums":
			_, _ = writer.Write([]byte(checksums))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	target := filepath.Join(t.TempDir(), "tsok")
	if err := os.WriteFile(target, []byte("old tsok binary"), 0755); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	updated, err := updateExecutable(t.Context(), server.Client(), server.URL+"/latest", target, "linux", "amd64", "v0.1.1", &output)
	if err != nil {
		t.Fatal(err)
	}
	if !updated {
		t.Fatal("updateExecutable() did not report an update")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new tsok binary" {
		t.Fatalf("updated binary = %q", got)
	}
	if got := output.String(); got != "Updated tsok from v0.1.1 to v0.2.0\n" {
		t.Fatalf("output = %q", got)
	}
}

func TestUpdateExecutableRejectsBadChecksum(t *testing.T) {
	archive := testReleaseArchive(t, []byte("untrusted binary"))
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/latest":
			_ = json.NewEncoder(writer).Encode(releaseInfo{
				TagName: "v0.2.0",
				Assets: []releaseAsset{
					{Name: "tsok_linux_amd64.tar.gz", URL: server.URL + "/archive"},
					{Name: "tsok_0.2.0_SHA256SUMS", URL: server.URL + "/checksums"},
				},
			})
		case "/archive":
			_, _ = writer.Write(archive)
		case "/checksums":
			_, _ = fmt.Fprintln(writer, strings.Repeat("0", 64), " tsok_linux_amd64.tar.gz")
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	targetDir := t.TempDir()
	target := filepath.Join(targetDir, "tsok")
	if err := os.WriteFile(target, []byte("old tsok binary"), 0755); err != nil {
		t.Fatal(err)
	}
	_, err := updateExecutable(t.Context(), server.Client(), server.URL+"/latest", target, "linux", "amd64", "v0.1.1", io.Discard)
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error = %v, want checksum mismatch", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old tsok binary" {
		t.Fatalf("original binary changed to %q", got)
	}
	matches, err := filepath.Glob(filepath.Join(targetDir, ".tsok-update-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary update files remain: %v", matches)
	}
}

func TestUpdateExecutableAlreadyCurrent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(writer).Encode(releaseInfo{TagName: "v0.1.1"})
	}))
	defer server.Close()

	var output bytes.Buffer
	updated, err := updateExecutable(t.Context(), server.Client(), server.URL, filepath.Join(t.TempDir(), "tsok"), "darwin", "arm64", "0.1.1", &output)
	if err != nil {
		t.Fatal(err)
	}
	if updated {
		t.Fatal("current version reported an update")
	}
	if got := output.String(); got != "tsok v0.1.1 is already up to date\n" {
		t.Fatalf("output = %q", got)
	}
}

func TestRunAutoUpdateAtMostOncePerDay(t *testing.T) {
	t.Setenv("TSOK_NO_AUTO_UPDATE", "")
	now := time.Date(2026, time.August, 23, 12, 0, 0, 0, time.UTC)
	updateCalls := 0
	cacheFile := filepath.Join(t.TempDir(), "tsok", "update-check")
	config := autoUpdateConfig{
		cacheFile:      cacheFile,
		currentVersion: "v0.1.2",
		now:            func() time.Time { return now },
		update: func(_ context.Context, out io.Writer) (bool, error) {
			updateCalls++
			_, _ = io.WriteString(out, "Updated tsok from v0.1.2 to v0.1.3\n")
			return true, nil
		},
	}

	var output bytes.Buffer
	runAutoUpdate(t.Context(), config, &output)
	if updateCalls != 1 {
		t.Fatalf("update calls = %d, want 1", updateCalls)
	}
	if output.String() != "Updated tsok from v0.1.2 to v0.1.3\n" {
		t.Fatalf("output = %q", output.String())
	}

	now = now.Add(23 * time.Hour)
	runAutoUpdate(t.Context(), config, io.Discard)
	if updateCalls != 1 {
		t.Fatalf("update calls within interval = %d, want 1", updateCalls)
	}

	now = now.Add(time.Hour)
	runAutoUpdate(t.Context(), config, io.Discard)
	if updateCalls != 2 {
		t.Fatalf("update calls after interval = %d, want 2", updateCalls)
	}
}

func TestRunAutoUpdateSkipsDevelopmentBuildsAndOptOut(t *testing.T) {
	updateCalls := 0
	config := autoUpdateConfig{
		cacheFile:      filepath.Join(t.TempDir(), "update-check"),
		currentVersion: "v0.0.0-devel",
		now:            time.Now,
		update: func(context.Context, io.Writer) (bool, error) {
			updateCalls++
			return true, nil
		},
	}
	t.Setenv("TSOK_NO_AUTO_UPDATE", "")
	runAutoUpdate(t.Context(), config, io.Discard)

	config.currentVersion = "v0.1.2"
	t.Setenv("TSOK_NO_AUTO_UPDATE", "1")
	runAutoUpdate(t.Context(), config, io.Discard)
	if updateCalls != 0 {
		t.Fatalf("update calls = %d, want 0", updateCalls)
	}
}

func TestRunAutoUpdateFailureDoesNotRepeatImmediately(t *testing.T) {
	t.Setenv("TSOK_NO_AUTO_UPDATE", "")
	updateCalls := 0
	config := autoUpdateConfig{
		cacheFile:      filepath.Join(t.TempDir(), "update-check"),
		currentVersion: "v0.1.2",
		now:            time.Now,
		update: func(context.Context, io.Writer) (bool, error) {
			updateCalls++
			return false, errors.New("network unavailable")
		},
	}
	runAutoUpdate(t.Context(), config, io.Discard)
	runAutoUpdate(t.Context(), config, io.Discard)
	if updateCalls != 1 {
		t.Fatalf("update calls = %d, want 1", updateCalls)
	}
}

func TestAutoUpdateAndRestart(t *testing.T) {
	t.Setenv("TSOK_NO_AUTO_UPDATE", "")
	restartCalls := 0
	config := autoUpdateConfig{
		cacheFile:      filepath.Join(t.TempDir(), "update-check"),
		currentVersion: "v0.1.3",
		now:            time.Now,
		update: func(context.Context, io.Writer) (bool, error) {
			return true, nil
		},
		restart: func() error {
			restartCalls++
			return nil
		},
	}
	restarted, err := autoUpdateAndRestart(t.Context(), config, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !restarted || restartCalls != 1 {
		t.Fatalf("restarted = %v, restart calls = %d", restarted, restartCalls)
	}

	restarted, err = autoUpdateAndRestart(t.Context(), config, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if restarted || restartCalls != 1 {
		t.Fatalf("cached restarted = %v, restart calls = %d", restarted, restartCalls)
	}
}

func TestAutoUpdateRestartFailureReturnsError(t *testing.T) {
	t.Setenv("TSOK_NO_AUTO_UPDATE", "")
	config := autoUpdateConfig{
		cacheFile:      filepath.Join(t.TempDir(), "update-check"),
		currentVersion: "v0.1.3",
		now:            time.Now,
		update: func(context.Context, io.Writer) (bool, error) {
			return true, nil
		},
		restart: func() error {
			return errors.New("exec denied")
		},
	}
	restarted, err := autoUpdateAndRestart(t.Context(), config, io.Discard)
	if restarted {
		t.Fatal("restart failure reported success")
	}
	if err == nil || !strings.Contains(err.Error(), "run the command again") {
		t.Fatalf("error = %v, want rerun guidance", err)
	}
}

func testReleaseArchive(t *testing.T, binary []byte) []byte {
	t.Helper()
	var archive bytes.Buffer
	gzipWriter := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{Name: "tsok", Mode: 0755, Size: int64(len(binary))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(binary); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}
