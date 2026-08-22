package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"tailscale.com/types/ptr"

	"github.com/coder/serpent"
	"github.com/coder/wush/cliui"
	"github.com/coder/wush/tsserver"
)

func rsyncCmd() *serpent.Command {
	var (
		verbose bool
		logger  = new(slog.Logger)
		logf    = func(str string, args ...any) {}

		overlayOpts = new(sendOverlayOpts)
	)
	return &serpent.Command{
		Use:   "rsync [flags] -- [rsync args]",
		Short: "Transfer files with rsync to/from a wush server.",
		Long: "Use " + cliui.Code("wush serve") + " on the computer you would like to transfer files to." +
			"\n\n" +
			formatExamples(
				example{
					Description: "Upload a local file",
					Command:     "wush rsync /local/path :/remote/path",
				},
				example{
					Description: "Download a remote file",
					Command:     "wush rsync :/remote/path /local/path",
				},
				example{
					Description: "Add rsync flags",
					Command:     "wush rsync /local/path :/remote/path -- --progress --stats -avz --human-readable",
				},
			),
		Middleware: serpent.Chain(
			initLogger(&verbose, ptr.To(false), logger, &logf),
			initAuth(&overlayOpts.authKey, &overlayOpts.clientAuth),
		),
		Handler: func(inv *serpent.Invocation) error {
			ctx := inv.Context()

			dm, err := tsserver.DERPMapTailscale(inv.Context())
			if err != nil {
				return err
			}
			overlayOpts.clientAuth.PrintDebug(logf, dm)

			progPath := os.Args[0]
			args := buildRsyncArgs(progPath, inv.Args, overlayOpts, verbose)
			_, _ = fmt.Fprintf(inv.Stderr, "Running rsync %q\n", inv.Args)
			cmd := exec.CommandContext(ctx, "rsync", args...)
			// The nested `wush ssh` process inherits this without exposing the
			// auth key in either rsync's or wush's command-line arguments.
			cmd.Env = append(cmd.Environ(), "WUSH_AUTH_KEY="+overlayOpts.clientAuth.AuthKey())
			cmd.Stdin = inv.Stdin
			cmd.Stdout = inv.Stdout
			cmd.Stderr = inv.Stderr

			if err := cmd.Run(); err != nil {
				return fmt.Errorf("run rsync: %w", err)
			}
			return nil
		},
		Options: []serpent.Option{
			{
				Flag:        "auth-key",
				Env:         "WUSH_AUTH_KEY",
				Description: "The auth key returned by " + cliui.Code("wush serve") + ". If not provided, it will be asked for on startup.",
				Default:     "",
				Value:       serpent.StringOf(&overlayOpts.authKey),
			},
			{
				Flag:        "wait-p2p",
				Description: waitDirectDescription,
				Default:     "false",
				Value:       serpent.BoolOf(&overlayOpts.waitP2P),
			},
			{
				Flag:          "verbose",
				FlagShorthand: "v",
				Description:   "Enable verbose logging.",
				Default:       "false",
				Value:         serpent.BoolOf(&verbose),
			},
		},
	}
}

func buildRsyncArgs(progPath string, args []string, overlayOpts *sendOverlayOpts, verbose bool) []string {
	remoteShell := []string{progPath, "ssh", "--quiet"}
	if overlayOpts.waitP2P {
		remoteShell = append(remoteShell, "--wait-p2p")
	}
	if verbose {
		remoteShell = append(remoteShell, "--verbose")
	}
	remoteShell = append(remoteShell, "--")

	quoted := make([]string, len(remoteShell))
	for i, arg := range remoteShell {
		quoted[i] = quoteShellArg(arg)
	}

	result := make([]string, 0, len(args)+2)
	result = append(result, "-e", strings.Join(quoted, " "))
	return append(result, args...)
}

func quoteShellArg(arg string) string {
	return "'" + strings.ReplaceAll(arg, "'", `'"'"'`) + "'"
}
