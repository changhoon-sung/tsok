//go:build windows

package xssh

import (
	"context"
	"fmt"
	"os/exec"

	"golang.org/x/sys/windows"
)

func configureCommand(_ *exec.Cmd, _ bool) {}

func waitPTYCommand(ctx context.Context, cmd *exec.Cmd) error {
	const waitIntervalMillis = 50

	handle, err := windows.OpenProcess(
		windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE,
		false,
		uint32(cmd.Process.Pid),
	)
	if err != nil {
		return fmt.Errorf("open PTY process: %w", err)
	}
	defer windows.CloseHandle(handle)

	for {
		result, err := windows.WaitForSingleObject(handle, waitIntervalMillis)
		if err != nil {
			return fmt.Errorf("wait for PTY process: %w", err)
		}
		if result == windows.WAIT_OBJECT_0 {
			var code uint32
			if err := windows.GetExitCodeProcess(handle, &code); err != nil {
				return fmt.Errorf("get PTY process exit code: %w", err)
			}
			if code == 0 {
				return nil
			}
			return &exitStatusError{code: int(code)}
		}
		if result != uint32(windows.WAIT_TIMEOUT) {
			return fmt.Errorf("wait for PTY process returned unexpected status %d", result)
		}
		select {
		case <-ctx.Done():
			_ = windows.TerminateProcess(handle, 1)
			return ctx.Err()
		default:
		}
	}
}
