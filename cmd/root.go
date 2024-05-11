package cmd

import (
	"eapm-ebpf/agent"
	"eapm-ebpf/common"
	"fmt"
	"os"
	"time"

	"github.com/jefurry/logrus"
	"github.com/jefurry/logrus/hooks/rotatelog"
	"github.com/sevlyar/go-daemon"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var logger *logrus.Logger = common.Log

var rootCmd = &cobra.Command{
	Use:   "eapm-ebpf",
	Short: "eapm-ebpf is an eBPF agent of eAPM",
	Long:  `An easy to use extension of famous apm system, gain the ability of inspect network latency`,
	Run: func(cmd *cobra.Command, args []string) {
		initLog()
		logger.Println("run eAPM eBPF Agent ...")
		logger.Printf("collector-addr: %s\n", viper.GetString(common.CollectorAddrVarName))
		if viper.GetBool(common.DaemonVarName) {
			cntxt := &daemon.Context{
				PidFileName: "./eapm-ebpf.pid",
				PidFilePerm: 0644,
				LogFileName: "./eapm-ebpf.log",
				LogFilePerm: 0640,
				WorkDir:     "./",
				// Umask:       027,
				Args: nil, // use current os args
			}
			d, err := cntxt.Reborn()
			if err != nil {
				logger.Fatal("Unable to run: ", err)
			}
			if d != nil {
				logger.Println("eAPM eBPF agent started!")
				return
			}
			defer cntxt.Release()
			logger.Println("----------------------")
			logger.Println("eAPM eBPF agent started!")
			agent.SetupAgent()
		} else {
			initLog()
			agent.SetupAgent()
		}
	},
}

var CollectorAddr string
var LocalMode bool
var ConsoleOutput bool
var Verbose bool
var Daemon bool
var LogDir string

func init() {
	rootCmd.Flags().StringVar(&CollectorAddr, "collector-addr", "localhost:18800", "backend collector address")
	rootCmd.Flags().StringVar(&LogDir, "log-dir", "", "log file dir")
	rootCmd.Flags().BoolVar(&LocalMode, "local-mode", false, "set true then do not export data to collector")
	rootCmd.Flags().BoolVarP(&ConsoleOutput, "console-output", "c", true, "print trace data to console")
	rootCmd.Flags().BoolVarP(&Verbose, "verbose", "v", true, "print verbose log")
	rootCmd.Flags().BoolVarP(&Daemon, "daemon", "d", false, "run in background")
	viper.BindPFlags(rootCmd.Flags())
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
	}
}

func initLog() {
	if viper.GetBool(common.VerboseVarName) {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
	if viper.GetBool(common.ConsoleOutputVarName) {
		logger.SetOut(os.Stdout)
	}

	logdir := viper.GetString(common.LogDirVarName)
	if logdir != "" {
		hook, err := rotatelog.NewHook(
			logdir+"/eapm-ebpf.log.%Y%m%d",
			rotatelog.WithMaxAge(time.Hour*24),
			rotatelog.WithRotationTime(time.Hour),
		)
		if err == nil {
			logger.Hooks.Add(hook)
		}
	}
}
