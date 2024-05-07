package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version number of eAPM eBPF Agent",
	Long:  `Print version number of eAPM eBPF Agent`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("eAPM eBPF Agent version v1.0.0 -- Release")
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
