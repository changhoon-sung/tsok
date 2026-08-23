//go:build !windows

package xssh

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	ssh "golang.org/x/crypto/ssh"
)

func TestServerRunsCommands(t *testing.T) {
	t.Parallel()

	server, listener := startTestServer(t)
	t.Cleanup(func() { _ = server.Close() })

	client := dialTestServer(t, listener.Addr().String())
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	output, err := session.CombinedOutput("printf 'tsok-ssh'")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(output), "tsok-ssh"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestServerDoesNotWaitForOpenStdin(t *testing.T) {
	t.Parallel()

	server, listener := startTestServer(t)
	t.Cleanup(func() { _ = server.Close() })

	client := dialTestServer(t, listener.Addr().String())
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	stdin, stdinWriter := io.Pipe()
	defer stdin.Close()
	defer stdinWriter.Close()
	session.Stdin = stdin

	type commandResult struct {
		output []byte
		err    error
	}
	done := make(chan commandResult, 1)
	go func() {
		output, err := session.CombinedOutput("printf 'tsok-ssh'")
		done <- commandResult{output: output, err: err}
	}()

	select {
	case result := <-done:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if got, want := string(result.output), "tsok-ssh"; got != want {
			t.Fatalf("output = %q, want %q", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("remote command waited for stdin EOF")
	}
}

func TestServerPreservesExitStatus(t *testing.T) {
	t.Parallel()

	server, listener := startTestServer(t)
	t.Cleanup(func() { _ = server.Close() })

	client := dialTestServer(t, listener.Addr().String())
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	err = session.Run("exit 7")
	var exitErr *ssh.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("error = %v, want *ssh.ExitError", err)
	}
	if got, want := exitErr.ExitStatus(), 7; got != want {
		t.Fatalf("exit status = %d, want %d", got, want)
	}
}

func TestServerRunsPTY(t *testing.T) {
	t.Parallel()

	server, listener := startTestServer(t)
	t.Cleanup(func() { _ = server.Close() })

	client := dialTestServer(t, listener.Addr().String())
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.RequestPty("tsok-test", 24, 80, ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}); err != nil {
		t.Fatal(err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	output := bufio.NewReader(stdout)
	command := `printf 'ready\n'; printf 'term=%s tty=%s\n' "$TERM" "${SSH_TTY:+set}"; sleep 0.2; printf 'speed='; stty speed; printf 'size='; stty size`
	if err := session.Start(command); err != nil {
		t.Fatal(err)
	}
	ready, err := output.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(ready) != "ready" {
		t.Fatalf("first PTY output = %q, want ready", ready)
	}
	if err := session.WindowChange(40, 100); err != nil {
		t.Fatal(err)
	}
	rest, err := io.ReadAll(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Wait(); err != nil {
		t.Fatal(err)
	}

	got := strings.ReplaceAll(string(rest), "\r", "")
	for _, want := range []string{"term=tsok-test tty=set", "size=40 100"} {
		if !strings.Contains(got, want) {
			t.Fatalf("PTY output %q does not contain %q", got, want)
		}
	}
	if strings.Contains(got, "speed=0") {
		t.Fatalf("PTY output reports disabled terminal speed: %q", got)
	}
}

func TestServerDrainsPTYOutput(t *testing.T) {
	t.Parallel()

	server, listener := startTestServer(t)
	t.Cleanup(func() { _ = server.Close() })

	client := dialTestServer(t, listener.Addr().String())
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.RequestPty("tsok-test", 24, 80, ssh.TerminalModes{
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}); err != nil {
		t.Fatal(err)
	}

	const bodySize = 256 * 1024
	output, err := session.CombinedOutput(`dd if=/dev/zero bs=1024 count=256 2>/dev/null | tr '\000' x; printf END`)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(output), bodySize+len("END"); got != want {
		t.Fatalf("PTY output length = %d, want %d; tail = %q", got, want, output[max(0, got-32):])
	}
	if !strings.HasSuffix(string(output), "END") {
		t.Fatalf("PTY output tail = %q, want END marker", output[len(output)-min(len(output), 32):])
	}
}

func TestServerAllowsOneSessionPerConnection(t *testing.T) {
	t.Parallel()

	server, listener := startTestServer(t)
	t.Cleanup(func() { _ = server.Close() })

	client := dialTestServer(t, listener.Addr().String())
	defer client.Close()

	first, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if err := first.Start("sleep 5"); err != nil {
		t.Fatal(err)
	}

	if _, err := client.NewSession(); err == nil {
		t.Fatal("second session unexpectedly succeeded")
	}
}

func TestServerCloseTerminatesActiveSession(t *testing.T) {
	t.Parallel()

	server, listener := startTestServer(t)
	client := dialTestServer(t, listener.Addr().String())
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Start("sleep 30"); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("active SSH session did not exit after server close")
	}
}

func TestSignalExitCode(t *testing.T) {
	t.Parallel()

	err := exec.Command("sh", "-c", "kill -TERM $$").Run()
	if err == nil {
		t.Fatal("signal command unexpectedly succeeded")
	}
	if got, want := exitCode(err), 255; got != want {
		t.Fatalf("exit code = %d, want %d", got, want)
	}
}

func startTestServer(t *testing.T) (*sshServer, net.Listener) {
	t.Helper()
	server, err := NewServer()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	return &sshServer{close: server.Close}, listener
}

type sshServer struct {
	close func() error
}

func (s *sshServer) Close() error {
	return s.close()
}

func dialTestServer(t *testing.T, address string) *ssh.Client {
	t.Helper()
	client, err := ssh.Dial("tcp", address, &ssh.ClientConfig{
		User:            "tsok-test",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}
