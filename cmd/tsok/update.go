package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/coder/serpent"
)

const (
	latestReleaseURL = "https://api.github.com/repos/changhoon-sung/tsok/releases/latest"
	maxArchiveSize   = 128 << 20
	maxChecksumSize  = 1 << 20
)

type releaseAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

type releaseInfo struct {
	TagName string         `json:"tag_name"`
	Assets  []releaseAsset `json:"assets"`
}

func updateCmd() *serpent.Command {
	return &serpent.Command{
		Use:   "update",
		Short: "Update tsok to the latest release.",
		Handler: func(inv *serpent.Invocation) error {
			executable, err := os.Executable()
			if err != nil {
				return fmt.Errorf("locate current executable: %w", err)
			}
			executable, err = filepath.EvalSymlinks(executable)
			if err != nil {
				return fmt.Errorf("resolve current executable: %w", err)
			}
			return updateExecutable(inv.Context(), http.DefaultClient, latestReleaseURL, executable, runtime.GOOS, runtime.GOARCH, getBuildInfo().version, inv.Stdout)
		},
		Options: serpent.OptionSet{},
	}
}

func updateExecutable(ctx context.Context, client *http.Client, releaseURL, executable, goos, goarch, currentVersion string, out io.Writer) error {
	if goos != "linux" && goos != "darwin" {
		return fmt.Errorf("unsupported OS: %s", goos)
	}
	if goarch != "amd64" && goarch != "arm64" {
		return fmt.Errorf("unsupported architecture: %s", goarch)
	}

	release, err := fetchRelease(ctx, client, releaseURL)
	if err != nil {
		return err
	}
	if release.TagName == "" {
		return errors.New("latest release has no tag")
	}
	if normalizeVersion(currentVersion) == normalizeVersion(release.TagName) {
		_, _ = fmt.Fprintf(out, "tsok %s is already up to date\n", release.TagName)
		return nil
	}

	archiveName := fmt.Sprintf("tsok_%s_%s.tar.gz", goos, goarch)
	checksumName := fmt.Sprintf("tsok_%s_SHA256SUMS", normalizeVersion(release.TagName))
	archiveURL, checksumURL := "", ""
	for _, asset := range release.Assets {
		switch asset.Name {
		case archiveName:
			archiveURL = asset.URL
		case checksumName:
			checksumURL = asset.URL
		}
	}
	if archiveURL == "" {
		return fmt.Errorf("release %s has no %s asset", release.TagName, archiveName)
	}
	if checksumURL == "" {
		return fmt.Errorf("release %s has no %s asset", release.TagName, checksumName)
	}

	targetDir := filepath.Dir(executable)
	archive, err := os.CreateTemp(targetDir, ".tsok-update-*.tar.gz")
	if err != nil {
		return fmt.Errorf("create update file beside executable: %w", err)
	}
	archivePath := archive.Name()
	defer os.Remove(archivePath)

	if err := downloadTo(ctx, client, archiveURL, archive, maxArchiveSize); err != nil {
		archive.Close()
		return fmt.Errorf("download %s: %w", archiveName, err)
	}
	if err := archive.Close(); err != nil {
		return fmt.Errorf("close downloaded archive: %w", err)
	}

	checksums, err := downloadBytes(ctx, client, checksumURL, maxChecksumSize)
	if err != nil {
		return fmt.Errorf("download %s: %w", checksumName, err)
	}
	if err := verifyArchive(archivePath, archiveName, checksums); err != nil {
		return err
	}

	replacement, err := os.CreateTemp(targetDir, ".tsok-update-*")
	if err != nil {
		return fmt.Errorf("create replacement executable: %w", err)
	}
	replacementPath := replacement.Name()
	defer os.Remove(replacementPath)
	if err := extractExecutable(archivePath, replacement); err != nil {
		replacement.Close()
		return err
	}
	if err := replacement.Chmod(0755); err != nil {
		replacement.Close()
		return fmt.Errorf("set replacement permissions: %w", err)
	}
	if err := replacement.Sync(); err != nil {
		replacement.Close()
		return fmt.Errorf("sync replacement executable: %w", err)
	}
	if err := replacement.Close(); err != nil {
		return fmt.Errorf("close replacement executable: %w", err)
	}
	if err := os.Rename(replacementPath, executable); err != nil {
		return fmt.Errorf("replace current executable: %w", err)
	}

	_, _ = fmt.Fprintf(out, "Updated tsok from %s to %s\n", currentVersion, release.TagName)
	return nil
}

func fetchRelease(ctx context.Context, client *http.Client, url string) (releaseInfo, error) {
	var release releaseInfo
	response, err := get(ctx, client, url)
	if err != nil {
		return release, fmt.Errorf("get latest release: %w", err)
	}
	defer response.Body.Close()
	if err := json.NewDecoder(io.LimitReader(response.Body, maxChecksumSize)).Decode(&release); err != nil {
		return release, fmt.Errorf("decode latest release: %w", err)
	}
	return release, nil
}

func downloadTo(ctx context.Context, client *http.Client, url string, dst io.Writer, limit int64) error {
	response, err := get(ctx, client, url)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.ContentLength > limit {
		return fmt.Errorf("response is too large: %d bytes", response.ContentLength)
	}
	written, err := io.Copy(dst, io.LimitReader(response.Body, limit+1))
	if err != nil {
		return err
	}
	if written > limit {
		return fmt.Errorf("response exceeds %d bytes", limit)
	}
	return nil
}

func downloadBytes(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	var data strings.Builder
	if err := downloadTo(ctx, client, url, &data, limit); err != nil {
		return nil, err
	}
	return []byte(data.String()), nil
}

func get(ctx context.Context, client *http.Client, url string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "tsok-updater")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		response.Body.Close()
		return nil, fmt.Errorf("%s returned %s", url, response.Status)
	}
	return response, nil
}

func verifyArchive(path, archiveName string, checksums []byte) error {
	want := ""
	for _, line := range strings.Split(string(checksums), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == archiveName {
			want = fields[0]
			break
		}
	}
	if want == "" {
		return fmt.Errorf("checksum file has no entry for %s", archiveName)
	}
	if len(want) != sha256.Size*2 {
		return fmt.Errorf("invalid SHA-256 checksum for %s", archiveName)
	}
	if _, err := hex.DecodeString(want); err != nil {
		return fmt.Errorf("invalid SHA-256 checksum for %s: %w", archiveName, err)
	}

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open downloaded archive: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("hash downloaded archive: %w", err)
	}
	got := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("checksum mismatch for %s", archiveName)
	}
	return nil
}

func extractExecutable(archivePath string, dst io.Writer) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open downloaded archive: %w", err)
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("open release archive: %w", err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	header, err := tarReader.Next()
	if err != nil {
		return fmt.Errorf("read release archive: %w", err)
	}
	if header.Name != "tsok" || !header.FileInfo().Mode().IsRegular() {
		return errors.New("release archive does not contain only the tsok binary")
	}
	if header.Size < 1 || header.Size > maxArchiveSize {
		return fmt.Errorf("invalid tsok binary size: %d", header.Size)
	}
	written, err := io.CopyN(dst, tarReader, header.Size)
	if err != nil {
		return fmt.Errorf("extract tsok binary: %w", err)
	}
	if written != header.Size {
		return fmt.Errorf("extracted %d bytes, expected %d", written, header.Size)
	}
	if _, err := tarReader.Next(); !errors.Is(err, io.EOF) {
		return errors.New("release archive contains unexpected files")
	}
	return nil
}

func normalizeVersion(value string) string {
	return strings.TrimPrefix(strings.TrimSpace(value), "v")
}
