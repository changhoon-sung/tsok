package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	if err := updateExecutable(t.Context(), server.Client(), server.URL+"/latest", target, "linux", "amd64", "v0.1.1", &output); err != nil {
		t.Fatal(err)
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
	err := updateExecutable(t.Context(), server.Client(), server.URL+"/latest", target, "linux", "amd64", "v0.1.1", io.Discard)
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
	err := updateExecutable(t.Context(), server.Client(), server.URL, filepath.Join(t.TempDir(), "tsok"), "darwin", "arm64", "0.1.1", &output)
	if err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "tsok v0.1.1 is already up to date\n" {
		t.Fatalf("output = %q", got)
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
