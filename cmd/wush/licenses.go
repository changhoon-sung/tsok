package main

import (
	"fmt"
	"strings"

	"github.com/coder/serpent"
)

func licensesCmd() *serpent.Command {
	return &serpent.Command{
		Use:   "licenses",
		Short: "Show open source dependency license information.",
		Handler: func(inv *serpent.Invocation) error {
			url := licenseReportURL(getBuildInfo().commitHash)
			_, err := fmt.Fprintf(inv.Stdout, `wush is built with open source dependencies.
Their license information for this build is available at:

    %s
`, url)
			return err
		},
	}
}

func licenseReportURL(commitHash string) string {
	ref := commitHash
	if ref == "" || strings.Trim(ref, "0") == "" {
		ref = "main"
	}
	return "https://github.com/changhoon-sung/wush/blob/" + ref + "/licenses/wush.md"
}
