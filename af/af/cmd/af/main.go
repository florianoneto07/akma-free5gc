/*
 * AF: AKMA Application Function (3GPP TS 33.535) serving the Ua* profiles of
 * TS 24.109 Annex K: HTTP Digest inside TLS (digest-tls), TLS 1.3 and TLS 1.2
 * with K_AF as pre-shared key (psk-tls13 and psk-tls12, with wolfSSL), and
 * for tests the simplified Ua* protocol of package uastar (digest-http).
 */

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
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
	"github.com/florianoneto07/akma-free5gc/af/af/internal/profile"
	"github.com/florianoneto07/akma-free5gc/af/af/internal/server"
	"github.com/florianoneto07/akma-free5gc/af/akmaoscore"
	"github.com/florianoneto07/akma-free5gc/af/akmatls"
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
	logger.MainLog.Infof("FQDN %s; realm %q; qop %v; nonce lifetime %s; K_AF expiry policy %s; anonymous %t",
		s.FQDN, s.Realm, s.Qop, s.NonceLifetime, s.KafExpiry, s.Anonymous)
	if profile.Built {
		logger.MainLog.Infof("Built with wolfSSL: PSK profiles available")
	}
	if s.ClockOffset != 0 {
		logger.MainLog.Warnf("Clock offset %s (test only): K_AF expiry is judged on a shifted clock", s.ClockOffset)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var keys server.KeyProvider
	if s.NefURI == "" {
		logger.MainLog.Infof("AF inside the operator network: K_AF from the AAnF at %s", s.AanfURI)
		keys = aanf.New(s.AanfURI, s.Anonymous)
	} else {
		host, _, _ := net.SplitHostPort(s.Profiles[0].Listen)
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
		keys = nef.New(s.NefURI, s.Anonymous, reg)
	}

	ua := server.New(s, keys)
	var running []*profile.Running
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, r := range running {
			r.Shutdown(shutdown)
		}
	}()
	for _, p := range s.Profiles {
		r, err := profile.Start(p, s, ua)
		if err != nil {
			return fmt.Errorf("Ua* server %s on %s: %w", p.Type, p.Listen, err)
		}
		running = append(running, r)
		logger.MainLog.Infof("Ua* server %s listening on %s for %s", p.Type, p.Listen, describe(p, s))
	}
	<-ctx.Done()
	logger.MainLog.Infof("AF terminated")
	return nil
}

// describe names the resource and the AF_ID of a profile, for the log.
func describe(p config.Profile, s *config.Settings) string {
	url := "https://" + s.FQDN + s.Path
	switch p.Type {
	case akmatls.ProfileDigestHTTP:
		return fmt.Sprintf("http://%s%s, AF_ID %s (simplified Ua*, test only)", s.FQDN, s.Path, s.AfID.Transport())
	case akmatls.ProfileDigestTLS:
		return url + ", AF_ID " + s.FQDN + ".010001<cipher suite> (TS 24.109 K.2)"
	case akmatls.ProfilePSKTLS13:
		return url + ", AF_ID " + s.FQDN + ".0100000007 (TS 24.109 K.3.3)"
	case akmatls.ProfilePSKDTLS13:
		return "coaps://" + s.FQDN + s.Path + ", AF_ID " + s.FQDN + ".0100000009 (TS 33.535 Annex C)"
	case akmatls.ProfilePSKDTLS12:
		return "coaps://" + s.FQDN + s.Path + ", AF_ID " + s.FQDN + ".010001<cipher suite> (DTLS 1.2)"
	case akmatls.ProfileOSCORE:
		return "coap://" + s.FQDN + akmaoscore.Path + " then " + s.Path + " under OSCORE, AF_ID " + s.FQDN +
			".0100000008 (TS 33.535 Annex D)"
	default:
		return url + ", AF_ID " + s.FQDN + ".010001<cipher suite> (TS 24.109 K.3.2)"
	}
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
