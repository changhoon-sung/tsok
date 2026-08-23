//go:build !windows

package xssh

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func configureCommand(cmd *exec.Cmd, hasPTY bool) {
	if !hasPTY {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			if errors.Is(err, syscall.ESRCH) {
				return os.ErrProcessDone
			}
			return err
		}
		return nil
	}
}

func waitPTYCommand(ctx context.Context, cmd *exec.Cmd) error {
	err := cmd.Wait()

	// charm SSH copies the PTY master to the SSH channel in an internal
	// goroutine. Close our parent-side slave after the child exits so that copy
	// sees EOF, then give it a bounded window to flush the final PTY bytes before
	// the session handler returns and closes the SSH channel.
	if closer, ok := cmd.Stdout.(io.Closer); ok {
		_ = closer.Close()
	}
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
	return err
}
