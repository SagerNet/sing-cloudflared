package cmd

import "github.com/spf13/cobra"

var mainCommand = &cobra.Command{
	Use:   "cloudflared",
	Short: "Cloudflare Tunnel client",
}

func Execute() error {
	return mainCommand.Execute()
}
