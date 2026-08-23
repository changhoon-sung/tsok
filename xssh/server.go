package xssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"time"

	ssh "charm.land/ssh"
	gossh "golang.org/x/crypto/ssh"
)

// NewServer returns an SSH server that runs commands as the current user.
// Authentication is provided by the encrypted tsok overlay, so the SSH layer
// intentionally does not add a second authentication mechanism.
func NewServer() (*ssh.Server, error) {
	server := &ssh.Server{
		Handler:                handleSession,
		SessionRequestCallback: snapshotSessionRequest,
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"session": singleSessionHandler,
		},
	}
	if err := server.SetOption(ssh.AllocatePty()); err != nil {
		return nil, fmt.Errorf("configure SSH PTY support: %w", err)
	}
	return server, nil
}

type contextKey uint8

const (
	singleSessionKey contextKey = iota
	sessionConfigKey
)

type sessionConfig struct {
	pty    ssh.Pty
	hasPTY bool
}

func snapshotSessionRequest(session ssh.Session, _ string) bool {
	pty, _, hasPTY := session.Pty()
	session.Context().SetValue(sessionConfigKey, sessionConfig{pty: pty, hasPTY: hasPTY})
	return true
}

func singleSessionHandler(server *ssh.Server, conn *gossh.ServerConn, newChannel gossh.NewChannel, ctx ssh.Context) {
	ctx.Lock()
	used, _ := ctx.Value(singleSessionKey).(bool)
	if !used {
		ctx.SetValue(singleSessionKey, true)
	}
	ctx.Unlock()

	if used {
		_ = newChannel.Reject(gossh.ResourceShortage, "tsok allows one session per SSH connection")
		return
	}

	ssh.DefaultSessionHandler(server, conn, newChannel, ctx)
	_ = conn.Close()
}

func handleSession(session ssh.Session) {
	err := runSession(session)
	if err == nil {
		return
	}

	var statusErr interface{ ExitCode() int }
	if !errors.As(err, &statusErr) && !errors.Is(err, context.Canceled) {
		_, _ = fmt.Fprintln(session.Stderr(), "ssh:", err)
	}
	_ = session.Exit(exitCode(err))
}

func runSession(session ssh.Session) error {
	config, ok := session.Context().Value(sessionConfigKey).(sessionConfig)
	if !ok {
		return errors.New("SSH session configuration is missing")
	}
	cmd, err := sessionCommand(session, config.pty, config.hasPTY)
	if err != nil {
		return err
	}

	cmd.WaitDelay = 5 * time.Second
	configureCommand(cmd, config.hasPTY)
	if config.hasPTY {
		if err := config.pty.Start(cmd, ssh.WithJobControl()); err != nil {
			return fmt.Errorf("start PTY command: %w", err)
		}
		return waitPTYCommand(session.Context(), cmd)
	}

	cmd.Stdout = session
	cmd.Stderr = session.Stderr()
	// Keep stdin copying outside os/exec. Its internal copier is part of Wait,
	// which makes commands that exit without reading stdin wait for SSH EOF.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("connect command stdin: %w", err)
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return err
	}
	go func() {
		_, _ = io.Copy(stdin, session)
		_ = stdin.Close()
	}()
	return cmd.Wait()
}

func sessionCommand(session ssh.Session, pty ssh.Pty, hasPTY bool) (*exec.Cmd, error) {
	shell, args := shellCommand(session.RawCommand())
	cmd := exec.CommandContext(session.Context(), shell, args...)

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get home directory: %w", err)
	}
	cmd.Dir = home

	env := append([]string{}, os.Environ()...)
	env = append(env, session.Environ()...)
	if currentUser, err := user.Current(); err == nil {
		env = append(env, "USER="+currentUser.Username, "LOGNAME="+currentUser.Username)
	}
	env = append(env, "SHELL="+shell)
	if hasPTY {
		env = append(env, "TERM="+pty.Term, "SSH_TTY="+pty.Name())
	}
	env = append(env, sshConnectionEnv(session)...)
	cmd.Env = env

	return cmd, nil
}

func shellCommand(rawCommand string) (string, []string) {
	if runtime.GOOS == "windows" {
		shell := executableFromEnv("COMSPEC", "cmd.exe")
		if rawCommand == "" {
			return shell, nil
		}
		return shell, []string{"/c", rawCommand}
	}

	shell := executableFromEnv("SHELL", "/bin/sh")
	if rawCommand == "" {
		return shell, []string{"-l"}
	}
	return shell, []string{"-c", rawCommand}
}

func executableFromEnv(name, fallback string) string {
	if candidate := os.Getenv(name); candidate != "" {
		if resolved, err := exec.LookPath(candidate); err == nil {
			return resolved
		}
	}
	return fallback
}

func sshConnectionEnv(session ssh.Session) []string {
	clientHost, clientPort := splitAddr(session.RemoteAddr())
	serverHost, serverPort := splitAddr(session.LocalAddr())
	return []string{
		"SSH_CLIENT=" + strings.Join([]string{clientHost, clientPort, serverPort}, " "),
		"SSH_CONNECTION=" + strings.Join([]string{clientHost, clientPort, serverHost, serverPort}, " "),
	}
}

func splitAddr(addr net.Addr) (string, string) {
	if addr == nil {
		return "0.0.0.0", "0"
	}
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String(), "0"
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return host, "0"
	}
	return host, port
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var statusErr interface{ ExitCode() int }
	if errors.As(err, &statusErr) {
		if code := statusErr.ExitCode(); code >= 0 {
			return code
		}
		return 255
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return 255
	}
	return 1
}

type exitStatusError struct {
	code int
}

func (e *exitStatusError) Error() string {
	return fmt.Sprintf("process exited with status %d", e.code)
}

func (e *exitStatusError) ExitCode() int {
	return e.code
}
