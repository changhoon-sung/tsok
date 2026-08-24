package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"go4.org/mem"
	"tailscale.com/types/key"

	"github.com/changhoon-sung/tsok/overlay"
)

const (
	persistedAuthStateVersion = 1
	maxPersistedAuthStateSize = 4 << 10
)

type persistedAuthState struct {
	Version            int    `json:"version"`
	ReceiverPrivateKey string `json:"receiver_private_key"`
	OverlayPrivateKey  string `json:"overlay_private_key"`
	DERPRegionID       uint16 `json:"derp_region_id"`
}

func resolvePersistFile(persist bool, persistFile string, rotate bool) (string, error) {
	persistFile = strings.TrimSpace(persistFile)
	if persist && persistFile != "" {
		return "", errors.New("--persist and --persist-file cannot be used together")
	}
	if rotate && !persist && persistFile == "" {
		return "", errors.New("--rotate-auth-key requires --persist or --persist-file")
	}
	if persist {
		return defaultPersistFile()
	}
	if persistFile == "" {
		return "", nil
	}
	abs, err := filepath.Abs(persistFile)
	if err != nil {
		return "", fmt.Errorf("resolve persist file: %w", err)
	}
	return abs, nil
}

func defaultPersistFile() (string, error) {
	if stateHome := os.Getenv("XDG_STATE_HOME"); stateHome != "" {
		if !filepath.IsAbs(stateHome) {
			return "", errors.New("XDG_STATE_HOME must be an absolute path")
		}
		return filepath.Join(stateHome, "tsok", "serve-state"), nil
	}
	if runtime.GOOS == "linux" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("get home directory: %w", err)
		}
		return filepath.Join(home, ".local", "state", "tsok", "serve-state"), nil
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("get user state directory: %w", err)
	}
	return filepath.Join(configDir, "tsok", "serve-state"), nil
}

func loadPersistedAuthState(path string) (overlay.ReceiveState, bool, error) {
	var state overlay.ReceiveState
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, false, nil
	}
	if err != nil {
		return state, false, fmt.Errorf("inspect persistent auth state: %w", err)
	}
	if !info.Mode().IsRegular() {
		return state, false, errors.New("persistent auth state must be a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return state, false, fmt.Errorf("open persistent auth state: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return state, false, fmt.Errorf("inspect opened persistent auth state: %w", err)
	}
	if !os.SameFile(info, openedInfo) {
		return state, false, errors.New("persistent auth state changed while opening")
	}
	if !openedInfo.Mode().IsRegular() {
		return state, false, errors.New("persistent auth state must be a regular file")
	}
	if openedInfo.Mode().Perm()&0077 != 0 {
		return state, false, fmt.Errorf("persistent auth state permissions are %04o, want 0600 or stricter", openedInfo.Mode().Perm())
	}
	if openedInfo.Size() > maxPersistedAuthStateSize {
		return state, false, fmt.Errorf("persistent auth state exceeds %d bytes", maxPersistedAuthStateSize)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPersistedAuthStateSize+1))
	if err != nil {
		return state, false, fmt.Errorf("read persistent auth state: %w", err)
	}
	if len(data) > maxPersistedAuthStateSize {
		return state, false, fmt.Errorf("persistent auth state exceeds %d bytes", maxPersistedAuthStateSize)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var persisted persistedAuthState
	if err := decoder.Decode(&persisted); err != nil {
		return state, false, fmt.Errorf("decode persistent auth state: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return state, false, err
	}
	if persisted.Version != persistedAuthStateVersion {
		return state, false, fmt.Errorf("unsupported persistent auth state version %d", persisted.Version)
	}

	receiverPrivate, err := decodePrivateKey("receiver", persisted.ReceiverPrivateKey)
	if err != nil {
		return state, false, err
	}
	overlayPrivate, err := decodePrivateKey("overlay", persisted.OverlayPrivateKey)
	if err != nil {
		return state, false, err
	}
	if persisted.DERPRegionID == 0 {
		return state, false, errors.New("persistent auth state has a zero DERP region")
	}
	return overlay.ReceiveState{
		ReceiverPrivateKey: receiverPrivate,
		OverlayPrivateKey:  overlayPrivate,
		DERPRegionID:       persisted.DERPRegionID,
	}, true, nil
}

func savePersistedAuthState(path string, state overlay.ReceiveState, replace bool) error {
	persisted, err := encodePersistedAuthState(state)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return fmt.Errorf("encode persistent auth state: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create persistent auth state directory: %w", err)
	}
	temporary, err := os.CreateTemp(dir, ".serve-state-*")
	if err != nil {
		return fmt.Errorf("create temporary auth state: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return fmt.Errorf("protect temporary auth state: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary auth state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary auth state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary auth state: %w", err)
	}

	if replace {
		if err := os.Rename(temporaryPath, path); err != nil {
			return fmt.Errorf("replace persistent auth state: %w", err)
		}
	} else {
		if err := os.Link(temporaryPath, path); err != nil {
			if errors.Is(err, os.ErrExist) {
				return errors.New("persistent auth state was created concurrently; run serve again")
			}
			return fmt.Errorf("create persistent auth state: %w", err)
		}
		if err := os.Remove(temporaryPath); err != nil {
			return fmt.Errorf("remove temporary auth state link: %w", err)
		}
	}

	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open persistent auth state directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync persistent auth state directory: %w", err)
	}
	return nil
}

func encodePersistedAuthState(state overlay.ReceiveState) (persistedAuthState, error) {
	var persisted persistedAuthState
	if state.ReceiverPrivateKey.IsZero() {
		return persisted, errors.New("receiver private key is zero")
	}
	if state.OverlayPrivateKey.IsZero() {
		return persisted, errors.New("overlay private key is zero")
	}
	if state.DERPRegionID == 0 {
		return persisted, errors.New("DERP region ID is zero")
	}
	receiverRaw := state.ReceiverPrivateKey.Raw32()
	overlayRaw := state.OverlayPrivateKey.Raw32()
	return persistedAuthState{
		Version:            persistedAuthStateVersion,
		ReceiverPrivateKey: base64.RawStdEncoding.EncodeToString(receiverRaw[:]),
		OverlayPrivateKey:  base64.RawStdEncoding.EncodeToString(overlayRaw[:]),
		DERPRegionID:       state.DERPRegionID,
	}, nil
}

func decodePrivateKey(name, encoded string) (key.NodePrivate, error) {
	decoded, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return key.NodePrivate{}, fmt.Errorf("decode %s private key: %w", name, err)
	}
	if len(decoded) != 32 {
		return key.NodePrivate{}, fmt.Errorf("%s private key is %d bytes, want 32", name, len(decoded))
	}
	privateKey := key.NodePrivateFromRaw32(mem.B(decoded))
	if privateKey.IsZero() {
		return key.NodePrivate{}, fmt.Errorf("%s private key is zero", name)
	}
	return privateKey, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("persistent auth state has trailing JSON data")
		}
		return fmt.Errorf("decode trailing persistent auth state data: %w", err)
	}
	return nil
}
