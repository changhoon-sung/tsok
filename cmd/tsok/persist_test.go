package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/changhoon-sung/tsok/overlay"
)

func TestResolvePersistFile(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	path, err := resolvePersistFile(false, "", false)
	if err != nil || path != "" {
		t.Fatalf("ephemeral path = %q, error = %v", path, err)
	}
	path, err = resolvePersistFile(true, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(path, filepath.Join("tsok", "serve-state")) {
		t.Fatalf("default persistent path = %q", path)
	}

	custom := filepath.Join("relative", "serve-state")
	path, err = resolvePersistFile(false, custom, false)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(path) || !strings.HasSuffix(path, custom) {
		t.Fatalf("custom persistent path = %q", path)
	}

	if _, err := resolvePersistFile(true, custom, false); err == nil || !strings.Contains(err.Error(), "cannot be used together") {
		t.Fatalf("combined flags error = %v", err)
	}
	if _, err := resolvePersistFile(false, "", true); err == nil || !strings.Contains(err.Error(), "requires") {
		t.Fatalf("rotation without persistence error = %v", err)
	}
}

func TestServeCommandExposesPersistentAuthOptions(t *testing.T) {
	t.Parallel()

	flags := make(map[string]bool)
	for _, option := range serveCmd().Options {
		flags[option.Flag] = true
	}
	for _, want := range []string{"persist", "persist-file", "rotate-auth-key"} {
		if !flags[want] {
			t.Fatalf("serve command is missing --%s", want)
		}
	}
}

func TestDefaultPersistFileRejectsRelativeXDGStateHome(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "relative-state")
	if _, err := defaultPersistFile(); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("error = %v, want absolute path error", err)
	}
}

func TestPersistedAuthStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "serve-state")
	state := testReceiveState(21)
	if err := savePersistedAuthState(path, state, false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("state mode = %04o, want 0600", got)
	}
	loaded, found, err := loadPersistedAuthState(path)
	if err != nil {
		t.Fatal(err)
	}
	if !found || !reflect.DeepEqual(loaded, state) {
		t.Fatalf("loaded state = %#v, found = %v, want %#v", loaded, found, state)
	}
	dm := &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
		21: {RegionID: 21},
	}}
	beforeRestart, err := overlay.NewReceiveOverlayWithState(nil, nil, dm, state)
	if err != nil {
		t.Fatal(err)
	}
	afterRestart, err := overlay.NewReceiveOverlayWithState(nil, nil, dm, loaded)
	if err != nil {
		t.Fatal(err)
	}
	if beforeRestart.ClientAuth().AuthKey() != afterRestart.ClientAuth().AuthKey() {
		t.Fatal("auth key changed after persisted state reload")
	}
}

func TestPersistedAuthStateDoesNotClobberConcurrentCreation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serve-state")
	first := testReceiveState(21)
	second := testReceiveState(22)
	if err := savePersistedAuthState(path, first, false); err != nil {
		t.Fatal(err)
	}
	if err := savePersistedAuthState(path, second, false); err == nil || !strings.Contains(err.Error(), "created concurrently") {
		t.Fatalf("second save error = %v", err)
	}
	loaded, found, err := loadPersistedAuthState(path)
	if err != nil {
		t.Fatal(err)
	}
	if !found || !reflect.DeepEqual(loaded, first) {
		t.Fatalf("concurrent save changed state to %#v", loaded)
	}
}

func TestPersistedAuthStateRotationReplacesState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serve-state")
	first := testReceiveState(21)
	second := testReceiveState(22)
	if err := savePersistedAuthState(path, first, false); err != nil {
		t.Fatal(err)
	}
	if err := savePersistedAuthState(path, second, true); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := loadPersistedAuthState(path)
	if err != nil {
		t.Fatal(err)
	}
	if !found || !reflect.DeepEqual(loaded, second) {
		t.Fatalf("rotated state = %#v, want %#v", loaded, second)
	}
}

func TestLoadPersistedAuthStateRejectsUnsafeFiles(t *testing.T) {
	t.Run("permissions", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "serve-state")
		if err := savePersistedAuthState(path, testReceiveState(21), false); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := loadPersistedAuthState(path); err == nil || !strings.Contains(err.Error(), "permissions") {
			t.Fatalf("error = %v, want permissions error", err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		if err := os.WriteFile(target, []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "serve-state")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, _, err := loadPersistedAuthState(path); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("error = %v, want regular file error", err)
		}
	})

	t.Run("unknown field", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "serve-state")
		data := `{"version":1,"receiver_private_key":"x","overlay_private_key":"x","derp_region_id":1,"extra":true}`
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := loadPersistedAuthState(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("error = %v, want unknown field error", err)
		}
	})
}

func testReceiveState(region uint16) overlay.ReceiveState {
	return overlay.ReceiveState{
		ReceiverPrivateKey: key.NewNode(),
		OverlayPrivateKey:  key.NewNode(),
		DERPRegionID:       region,
	}
}
