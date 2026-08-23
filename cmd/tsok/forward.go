package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"

	"tailscale.com/tailcfg"

	"github.com/changhoon-sung/tsok/cliui"
	transportcore "github.com/changhoon-sung/tsok/internal/transport"
	"github.com/coder/serpent"
)

func forwardCmd() *serpent.Command {
	var (
		verbose    bool
		quiet      bool
		derpmapFi  string
		tcpStdio   string
		logger     = new(slog.Logger)
		logf       = func(str string, args ...any) {}
		waitDirect bool

		dm          *tailcfg.DERPMap
		authKey     string
		tcpForwards []string // <port>:<port>
		udpForwards []string // <port>:<port>
	)
	return &serpent.Command{
		Use:   "forward",
		Short: "Forward local endpoints to ports on the tsok server.",
		Long: formatExamples(
			example{
				Description: "Forward host TCP port 1234 to local port 5678",
				Command:     "tsok forward --tcp 5678:1234",
			},
			example{
				Description: "Forward a single UDP port",
				Command:     "tsok forward --udp 9000",
			},
			example{
				Description: "Forward stdin and stdout to a TCP port for OpenSSH ProxyCommand",
				Command:     "tsok forward --tcp-stdio 22",
			},
			example{
				Description: "Forward multiple TCP ports and a UDP port",
				Command:     "tsok forward --tcp 8080:8080 --tcp 9000:3000 --udp 5353:53",
			},
			example{
				Description: "Forward specifying the local address to bind",
				Command:     "tsok forward --tcp 1.2.3.4:8080:8080",
			},
		),
		Middleware: serpent.Chain(
			initLogger(&verbose, &quiet, logger, &logf),
			initAuth(&authKey),
			derpMap(&derpmapFi, &dm),
		),
		Handler: func(inv *serpent.Invocation) error {
			ctx, cancel := context.WithCancel(inv.Context())
			defer cancel()
			if tcpStdio != "" && (len(tcpForwards) != 0 || len(udpForwards) != 0) {
				return errors.New("--tcp-stdio cannot be combined with --tcp or --udp")
			}
			var stdioPort uint16
			if tcpStdio != "" {
				parsed, err := parsePort(tcpStdio)
				if err != nil {
					return fmt.Errorf("parse --tcp-stdio port: %w", err)
				}
				stdioPort = parsed
			}

			specs, err := parsePortForwards(tcpForwards, udpForwards)
			if err != nil {
				return fmt.Errorf("parse forward specs: %w", err)
			}
			if len(specs) == 0 && stdioPort == 0 {
				return errors.New("no forwards requested")
			}

			client, err := connectTransport(ctx, clientTransportOptions{
				authKey: authKey, waitP2P: waitDirect, derpMap: dm,
				verbose: verbose, logger: logger, logf: logf, logWriter: inv.Stderr,
			})
			if err != nil {
				return err
			}
			defer client.Close()

			if stdioPort != 0 {
				conn, err := client.DialTCP(ctx, stdioPort)
				if err != nil {
					return fmt.Errorf("dial TCP port %d in peer: %w", stdioPort, err)
				}
				return bridgeStdio(ctx, conn, inv.Stdin, inv.Stdout)
			}

			var (
				wg                = new(sync.WaitGroup)
				listeners         = make([]net.Listener, len(specs))
				closeAllListeners = func() {
					logger.Debug("closing all listeners")
					for _, l := range listeners {
						if l == nil {
							continue
						}
						_ = l.Close()
					}
				}
			)
			defer closeAllListeners()

			for i, spec := range specs {
				if spec.dialNetwork == "udp" {
					if err := client.OpenUDP(ctx, spec.dialAddress.Port()); err != nil {
						return fmt.Errorf("open UDP port %d in peer: %w", spec.dialAddress.Port(), err)
					}
				}
				l, err := listenAndForward(ctx, inv, client, wg, spec, logger)
				if err != nil {
					logger.Error("failed to listen", "spec", spec, "err", err)
					return err
				}
				listeners[i] = l
			}

			// Wait for the context to be canceled or for a signal and close
			// all listeners.
			var closeErr error
			wg.Add(1)
			go func() {
				defer wg.Done()

				sigs := make(chan os.Signal, 1)
				signal.Notify(sigs, os.Interrupt)
				defer signal.Stop(sigs)

				select {
				case <-ctx.Done():
					logger.Debug("command context expired waiting for signal", "err", ctx.Err())
					closeErr = ctx.Err()
				case sig := <-sigs:
					logger.Debug("received signal", "signal", sig)
					_, _ = fmt.Fprintln(inv.Stderr, "\nReceived signal, closing all listeners and active connections")
				}

				cancel()
				closeAllListeners()
			}()

			wg.Wait()
			return closeErr
		},
		Options: []serpent.Option{
			{
				Flag:        "auth-key",
				Env:         "TSOK_AUTH_KEY",
				Description: "The auth key returned by " + cliui.Code("tsok serve") + ". If not provided, it will be asked for on startup.",
				Default:     "",
				Value:       serpent.StringOf(&authKey),
			},
			{
				Flag:        "derp-config-file",
				Description: "File which specifies the DERP config to use. In the structure of https://pkg.go.dev/tailscale.com/tailcfg#DERPMap.",
				Default:     "",
				Value:       serpent.StringOf(&derpmapFi),
			},
			{
				Flag:        "wait-p2p",
				Description: waitDirectDescription,
				Default:     "false",
				Value:       serpent.BoolOf(&waitDirect),
			},
			{
				Flag:          "verbose",
				FlagShorthand: "v",
				Description:   "Enable verbose logging.",
				Default:       "false",
				Value:         serpent.BoolOf(&verbose),
			},
			{
				Flag:          "tcp",
				FlagShorthand: "p",
				Env:           "TSOK_FORWARD_TCP",
				Description:   "Forward TCP port(s) from the peer to the local machine.",
				Value:         serpent.StringArrayOf(&tcpForwards),
			},
			{
				Flag:        "udp",
				Env:         "TSOK_FORWARD_UDP",
				Description: "Forward UDP port(s) from the peer to the local machine. The UDP connection has TCP-like semantics to support stateful UDP protocols.",
				Value:       serpent.StringArrayOf(&udpForwards),
			},
			{
				Flag:        "tcp-stdio",
				Description: "Forward stdin and stdout to one TCP port on the peer.",
				Default:     "",
				Value:       serpent.StringOf(&tcpStdio),
			},
			{
				Flag:        "quiet",
				Description: "Silences diagnostic output.",
				Default:     "false",
				Value:       serpent.BoolOf(&quiet),
			},
		},
	}
}

func listenAndForward(
	ctx context.Context,
	inv *serpent.Invocation,
	client *transportcore.Client,
	wg *sync.WaitGroup,
	spec portForwardSpec,
	logger *slog.Logger,
) (net.Listener, error) {
	logger = logger.With("network", spec.listenNetwork, "address", spec.listenAddress)
	_, _ = fmt.Fprintf(inv.Stderr, "Forwarding '%v://%v' locally to '%v://%v' in the peer\n", spec.listenNetwork, spec.listenAddress, spec.dialNetwork, spec.dialAddress)

	l, err := inv.Net.Listen(spec.listenNetwork, spec.listenAddress.String())
	if err != nil {
		return nil, fmt.Errorf("listen '%v://%v': %w", spec.listenNetwork, spec.listenAddress, err)
	}
	logger.Debug("listening")

	wg.Add(1)
	go func(spec portForwardSpec) {
		defer wg.Done()
		for {
			netConn, err := l.Accept()
			if err != nil {
				// Listener implementations do not all wrap net.ErrClosed. Context
				// cancellation is the authoritative signal for a normal shutdown.
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					logger.Debug("listener closed")
					return
				}
				_, _ = fmt.Fprintf(inv.Stderr, "Error accepting connection from '%v://%v': %v\n", spec.listenNetwork, spec.listenAddress, err)
				_, _ = fmt.Fprintln(inv.Stderr, "Killing listener")
				return
			}
			logger.Debug("accepted connection", "remote_addr", netConn.RemoteAddr())

			go func(netConn net.Conn) {
				defer netConn.Close()
				remoteConn, err := client.Dial(ctx, spec.dialNetwork, spec.dialAddress.Port())
				if err != nil {
					_, _ = fmt.Fprintf(inv.Stderr, "Failed to dial '%v://%v' in peer: %s\n", spec.dialNetwork, spec.dialAddress, err)
					return
				}
				defer remoteConn.Close()
				logger.Debug("dialed remote", "remote_addr", netConn.RemoteAddr())

				if spec.dialNetwork == "udp" {
					copyDatagrams(ctx, netConn, remoteConn)
				} else {
					bicopy(ctx, netConn, remoteConn)
				}
				logger.Debug("connection closing", "remote_addr", netConn.RemoteAddr())
			}(netConn)
		}
	}(spec)

	return l, nil
}

func bridgeStdio(ctx context.Context, conn net.Conn, stdin io.Reader, stdout io.Writer) error {
	defer conn.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	stdinErr := make(chan error, 1)
	go func() {
		_, err := io.Copy(conn, stdin)
		if err == nil {
			if closeWriter, ok := conn.(interface{ CloseWrite() error }); ok {
				err = closeWriter.CloseWrite()
			}
		}
		stdinErr <- err
		if err != nil {
			_ = conn.Close()
		}
	}()

	_, stdoutErr := io.Copy(stdout, conn)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	select {
	case err := <-stdinErr:
		if err != nil {
			return fmt.Errorf("copy stdin to remote connection: %w", err)
		}
	default:
	}
	if stdoutErr != nil {
		return fmt.Errorf("copy remote connection to stdout: %w", stdoutErr)
	}
	return nil
}

func copyDatagrams(ctx context.Context, left, right net.Conn) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer left.Close()
	defer right.Close()

	var wg sync.WaitGroup
	copyOne := func(dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			n, err := src.Read(buf)
			if err != nil {
				cancel()
				return
			}
			if _, err := dst.Write(buf[:n]); err != nil {
				cancel()
				return
			}
		}
	}
	wg.Add(2)
	go copyOne(left, right)
	go copyOne(right, left)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-ctx.Done():
	case <-done:
	}
}

type portForwardSpec struct {
	listenNetwork string // tcp, udp
	listenAddress netip.AddrPort

	dialNetwork string // tcp, udp
	dialAddress netip.AddrPort
}

func parsePortForwards(tcpSpecs, udpSpecs []string) ([]portForwardSpec, error) {
	specs := []portForwardSpec{}

	for _, specEntry := range tcpSpecs {
		for _, spec := range strings.Split(specEntry, ",") {
			ports, err := parseSrcDestPorts(spec)
			if err != nil {
				return nil, fmt.Errorf("failed to parse TCP port-forward specification %q: %w", spec, err)
			}

			for _, port := range ports {
				specs = append(specs, portForwardSpec{
					listenNetwork: "tcp",
					listenAddress: port.local,
					dialNetwork:   "tcp",
					dialAddress:   port.remote,
				})
			}
		}
	}

	for _, specEntry := range udpSpecs {
		for _, spec := range strings.Split(specEntry, ",") {
			ports, err := parseSrcDestPorts(spec)
			if err != nil {
				return nil, fmt.Errorf("failed to parse UDP port-forward specification %q: %w", spec, err)
			}

			for _, port := range ports {
				specs = append(specs, portForwardSpec{
					listenNetwork: "udp",
					listenAddress: port.local,
					dialNetwork:   "udp",
					dialAddress:   port.remote,
				})
			}
		}
	}

	// Check for duplicate entries.
	locals := map[string]struct{}{}
	for _, spec := range specs {
		localStr := fmt.Sprintf("%v:%v", spec.listenNetwork, spec.listenAddress)
		if _, ok := locals[localStr]; ok {
			return nil, fmt.Errorf("local %v %v is specified twice", spec.listenNetwork, spec.listenAddress)
		}
		locals[localStr] = struct{}{}
	}

	return specs, nil
}

func parsePort(in string) (uint16, error) {
	port, err := strconv.ParseUint(strings.TrimSpace(in), 10, 16)
	if err != nil {
		return 0, fmt.Errorf("parse port %q: %w", in, err)
	}
	if port == 0 {
		return 0, errors.New("port cannot be 0")
	}

	return uint16(port), nil
}

type parsedSrcDestPort struct {
	local, remote netip.AddrPort
}

func parseSrcDestPorts(in string) ([]parsedSrcDestPort, error) {
	var (
		err        error
		parts      = strings.Split(in, ":")
		localAddr  = netip.AddrFrom4([4]byte{127, 0, 0, 1})
		remoteAddr = netip.AddrFrom4([4]byte{127, 0, 0, 1})
	)

	switch len(parts) {
	case 1:
		// Duplicate the single part
		parts = append(parts, parts[0])
	case 2:
		// Check to see if the first part is an IP address.
		_localAddr, err := netip.ParseAddr(parts[0])
		if err != nil {
			break
		}
		// The first part is the local address, so duplicate the port.
		localAddr = _localAddr
		parts = []string{parts[1], parts[1]}

	case 3:
		_localAddr, err := netip.ParseAddr(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid port specification %q; invalid ip %q: %w", in, parts[0], err)
		}
		localAddr = _localAddr
		parts = parts[1:]

	default:
		return nil, fmt.Errorf("invalid port specification %q", in)
	}

	if !strings.Contains(parts[0], "-") {
		localPort, err := parsePort(parts[0])
		if err != nil {
			return nil, fmt.Errorf("parse local port from %q: %w", in, err)
		}
		remotePort, err := parsePort(parts[1])
		if err != nil {
			return nil, fmt.Errorf("parse remote port from %q: %w", in, err)
		}

		return []parsedSrcDestPort{{
			local:  netip.AddrPortFrom(localAddr, localPort),
			remote: netip.AddrPortFrom(remoteAddr, remotePort),
		}}, nil
	}

	local, err := parsePortRange(parts[0])
	if err != nil {
		return nil, fmt.Errorf("parse local port range from %q: %w", in, err)
	}
	remote, err := parsePortRange(parts[1])
	if err != nil {
		return nil, fmt.Errorf("parse remote port range from %q: %w", in, err)
	}
	if len(local) != len(remote) {
		return nil, fmt.Errorf("port ranges must be the same length, got %d ports forwarded to %d ports", len(local), len(remote))
	}
	var out []parsedSrcDestPort
	for i := range local {
		out = append(out, parsedSrcDestPort{
			local:  netip.AddrPortFrom(localAddr, local[i]),
			remote: netip.AddrPortFrom(remoteAddr, remote[i]),
		})
	}
	return out, nil
}

func parsePortRange(in string) ([]uint16, error) {
	parts := strings.Split(in, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid port range specification %q", in)
	}
	start, err := parsePort(parts[0])
	if err != nil {
		return nil, fmt.Errorf("parse range start port from %q: %w", in, err)
	}
	end, err := parsePort(parts[1])
	if err != nil {
		return nil, fmt.Errorf("parse range end port from %q: %w", in, err)
	}
	if end < start {
		return nil, fmt.Errorf("range end port %v is less than start port %v", end, start)
	}
	var ports []uint16
	for i := uint32(start); i <= uint32(end); i++ {
		ports = append(ports, uint16(i))
	}
	return ports, nil
}
