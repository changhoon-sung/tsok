package main

import (
	"fmt"
	"time"

	"github.com/coder/serpent"
)

func versionCmd() *serpent.Command {
	cmd := &serpent.Command{
		Use:   "version",
		Short: "Output the tsok version.",
		Handler: func(inv *serpent.Invocation) error {
			bi := getBuildInfo()
			fmt.Printf("tsok %s-%s %s\n", bi.version, bi.commitHash[:7], bi.commitTime.Format(time.RFC1123))
			fmt.Printf("https://github.com/changhoon-sung/tsok/commit/%s\n", commit)
			return nil
		},
		Options: serpent.OptionSet{},
	}

	return cmd
}
