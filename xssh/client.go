package xssh

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/coder/serpent"
	"github.com/muesli/termenv"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
	"tailscale.com/tsnet"
)

func TailnetSSH(ctx context.Context, inv *serpent.Invocation, ts *tsnet.Server, addr string, stdio bool) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	conn, err := ts.Dial(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()

	// if stdio {
	// 	gnConn, ok := conn.(*gonet.TCPConn)
	// 	if !ok {
	// 		panic("ssh tcp conn is not *gonet.TCPConn")
	// 	}
	// }

	sshConn, channels, requests, err := ssh.NewClientConn(conn, "127.0.0.1:22", &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		return err
	}

	sshClient := ssh.NewClient(sshConn, channels, requests)
	defer sshClient.Close()
	sshSession, err := sshClient.NewSession()
	if err != nil {
		return err
	}
	defer sshSession.Close()

	sshSession.Stdin = inv.Stdin
	sshSession.Stdout = inv.Stdout
	sshSession.Stderr = inv.Stderr

	if command, ok := remoteCommand(inv.Args); ok {
		return sshSession.Run(command)
	}

	stdinFile, validIn := inv.Stdin.(*os.File)
	stdoutFile, validOut := inv.Stdout.(*os.File)
	interactive := validIn && validOut && term.IsTerminal(int(stdinFile.Fd())) && term.IsTerminal(int(stdoutFile.Fd()))
	width, height := 128, 128
	if interactive {
		inState, err := term.MakeRaw(int(stdinFile.Fd()))
		if err != nil {
			return err
		}
		defer func() {
			_ = term.Restore(int(stdinFile.Fd()), inState)
		}()
		restoreOutput, err := termenv.EnableVirtualTerminalProcessing(termenv.NewOutput(stdoutFile))
		if err != nil {
			return err
		}
		defer func() {
			_ = restoreOutput()
		}()
		if terminalWidth, terminalHeight, err := term.GetSize(int(stdoutFile.Fd())); err == nil {
			width, height = terminalWidth, terminalHeight
		}

		windowChange := ListenWindowSize(ctx)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-windowChange:
				}
				width, height, err := term.GetSize(int(stdoutFile.Fd()))
				if err != nil {
					continue
				}
				_ = sshSession.WindowChange(height, width)
			}
		}()
	}

	if interactive {
		terminalType := os.Getenv("TERM")
		if terminalType == "" {
			terminalType = "xterm-256color"
		}
		err = sshSession.RequestPty(terminalType, height, width, ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		})
		if err != nil {
			return fmt.Errorf("request pty: %w", err)
		}
	}

	err = sshSession.Shell()
	if err != nil {
		return fmt.Errorf("start shell: %w", err)
	}

	return sshSession.Wait()
}

func remoteCommand(args []string) (string, bool) {
	if len(args) == 0 {
		return "", false
	}
	return strings.Join(args, " "), true
}
