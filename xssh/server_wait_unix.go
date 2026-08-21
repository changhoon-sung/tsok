//go:build !windows

package xssh

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
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

func waitPTYCommand(_ context.Context, cmd *exec.Cmd) error {
	return cmd.Wait()
}
