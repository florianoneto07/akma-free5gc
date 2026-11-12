/*
 * CCF: CAPIF core function (3GPP TS 23.222, TS 29.222, TS 33.122)
 */

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/urfave/cli/v2"

	ccf_context "github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/context"
	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/credential"
	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/logger"
	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/pkg/factory"
	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/pkg/service"
	logger_util "github.com/free5gc/util/logger"
	"github.com/free5gc/util/version"
)

var CCF *service.CcfApp

func main() {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.MainLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	configFlag := &cli.StringFlag{
		Name:    "config",
		Aliases: []string{"c"},
		Usage:   "Load configuration from `FILE`",
	}
	app := cli.NewApp()
	app.Name = "ccf"
	app.Usage = "CAPIF core function (CCF)"
	app.Action = action
	app.Flags = []cli.Flag{
		configFlag,
		&cli.StringSliceFlag{
			Name:    "log",
			Aliases: []string{"l"},
			Usage:   "Output NF log to `FILE`",
		},
	}
	app.Commands = []*cli.Command{{
		Name:   "credential",
		Usage:  "Print an onboarding credential of an invoker profile (TS 33.122 cl. 6.1)",
		Action: credentialAction,
		Flags: []cli.Flag{
			configFlag,
			&cli.StringFlag{
				Name:     "profile",
				Usage:    "invoker profile of the configuration",
				Required: true,
			},
			&cli.DurationFlag{
				Name:  "validity",
				Usage: "validity of the credential",
				Value: 24 * time.Hour,
			},
		},
	}}

	if err := app.Run(os.Args); err != nil {
		logger.MainLog.Errorf("CCF Run error: %v\n", err)
		os.Exit(1)
	}
}

func action(cliCtx *cli.Context) error {
	if err := initLogFile(cliCtx.StringSlice("log")); err != nil {
		return err
	}

	logger.MainLog.Infoln("CCF version: ", version.GetVersion())

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh  // Wait for interrupt signal to gracefully shutdown
		cancel() // Notify each goroutine and wait them stopped
	}()

	cfg, err := factory.ReadConfig(cliCtx.String("config"))
	if err != nil {
		sigCh <- nil
		return err
	}
	factory.CcfConfig = cfg

	ccf, err := service.NewApp(ctx, cfg)
	if err != nil {
		sigCh <- nil
		return err
	}
	CCF = ccf

	ccf.Start()

	return nil
}

// credentialAction prints a credential on stdout; the log goes to stderr.
func credentialAction(cliCtx *cli.Context) error {
	cfg, err := factory.ReadConfig(cliCtx.String("config"))
	if err != nil {
		return err
	}
	profile := cliCtx.String("profile")
	if _, ok := cfg.Profile(profile); !ok {
		return fmt.Errorf("no invoker profile %q in the configuration", profile)
	}
	ctx, err := ccf_context.New(cfg)
	if err != nil {
		return err
	}
	token, err := credential.Issue(ctx.CredentialKey(), cfg.Configuration.CcfName, profile,
		time.Now(), cliCtx.Duration("validity"))
	if err != nil {
		return err
	}
	fmt.Println(token)
	return nil
}

// initLogFile adds the log files. Unlike the NFs of free5GC, the CCF does
// not write the TLS session keys next to the log.
func initLogFile(logNfPath []string) error {
	for _, path := range logNfPath {
		if err := logger_util.LogFileHook(logger.Log, path); err != nil {
			return err
		}
	}
	return nil
}
