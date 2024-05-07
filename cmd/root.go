package cmd

import (
	"eapm-ebpf/agent"
	"eapm-ebpf/common"
	"fmt"
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   "eapm-ebpf",
	Short: "eapm-ebpf is an eBPF agent of eAPM",
	Long:  `An easy to use extension of famous apm system, gain the ability of inspect network latency`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("run eAPM eBPF Agent ...")
		log.Printf("collector-addr: %s\n", viper.GetString(common.CollectorAddrVarName))
		agent.SetupAgent()
	},
}

var CollectorAddr string
var LocalMode bool
var ConsoleOutput bool
var Verbose bool

func init() {
	rootCmd.Flags().StringVar(&CollectorAddr, "collector-addr", "localhost:18800", "backend collector address")
	rootCmd.Flags().BoolVar(&LocalMode, "local-mode", false, "set true then do not export data to collector")
	rootCmd.Flags().BoolVarP(&ConsoleOutput, "console-output", "c", true, "print trace data to console")
	rootCmd.Flags().BoolVarP(&Verbose, "verbose", "v", true, "print verbose log")
	viper.BindPFlags(rootCmd.Flags())
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
	}
}
