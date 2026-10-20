/*
 * AF: AKMA Application Function (3GPP TS 33.535) serving the simplified Ua*
 * protocol of package uastar: HTTP Digest (RFC 7616) keyed with K_AF.
 */

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/florianoneto07/akma-free5gc/af/af/internal/aanf"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/config"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/logger"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/nef"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/nrf"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/server"
	logger_util "github.com/free5gc/util/logger"
)

func main() {
	cfgPath := flag.String("c", "config/afcfg.yaml", "configuration `file`")
	logPath := flag.String("l", "", "also write the log to `file`")
	flag.Parse()
	if err := run(*cfgPath, *logPath); err != nil {
		logger.MainLog.Errorf("AF: %v", err)
		os.Exit(1)
	}
}

func run(cfgPath, logPath string) error {
	if logPath != "" {
		if err := logger_util.LogFileHook(logger.Log, logPath); err != nil {
			return err
		}
	}
	s, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("configuration %s: %w", cfgPath, err)
	}
	logger.CfgLog.Infof("Read config from [%s]", cfgPath)
	if err := setLogger(s.Logger); err != nil {
		return err
	}
	logger.MainLog.Infof("AF_ID %s; realm %q; qop %v; nonce lifetime %s; K_AF expiry policy %s; anonymous %t",
		s.AfID.Transport(), s.Realm, s.Qop, s.NonceLifetime, s.KafExpiry, s.Anonymous)
	if s.ClockOffset != 0 {
		logger.MainLog.Warnf("Clock offset %s (test only): K_AF expiry is judged on a shifted clock", s.ClockOffset)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var keys server.KeyProvider
	if s.NefURI == "" {
		logger.MainLog.Infof("AF inside the operator network: K_AF from the AAnF at %s", s.AanfURI)
		keys = aanf.New(s.AanfURI, s.AfID, s.Anonymous)
	} else {
		host, _, _ := net.SplitHostPort(s.Listen)
		reg, err := nrf.Register(ctx, s.NrfURI, s.NfInstanceID, host)
		if err != nil {
			return fmt.Errorf("registration at the NRF %s: %w", s.NrfURI, err)
		}
		defer func() {
			if err := reg.Deregister(context.Background()); err != nil {
				logger.MainLog.Warnf("Deregistration at the NRF: %v", err)
				return
			}
			logger.MainLog.Infof("Deregistered from the NRF")
		}()
		logger.MainLog.Infof("AF outside the operator network: K_AF through the NEF at %s; "+
			"registered at the NRF %s as AF %s (OAuth2 %t)", s.NefURI, s.NrfURI, reg.NfID(), reg.OAuth2())
		keys = nef.New(s.NefURI, s.AfID, s.Anonymous, reg)
	}

	srv := &http.Server{
		Addr:              s.Listen,
		Handler:           server.New(s, keys),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	logger.MainLog.Infof("Ua* server listening on %s for http://%s%s", s.Listen, s.FQDN, s.Path)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	logger.MainLog.Infof("AF terminated")
	return nil
}

func setLogger(l config.Logger) error {
	if !l.Enable {
		logger.Log.SetOutput(nopWriter{})
	}
	if l.Level != "" {
		lvl, err := logrus.ParseLevel(l.Level)
		if err != nil {
			return fmt.Errorf("logger.level: %w", err)
		}
		logger.Log.SetLevel(lvl)
	}
	logger.Log.SetReportCaller(l.ReportCaller)
	return nil
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }
