package sbi

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/logger"
	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/pkg/app"
	"github.com/free5gc/openapi/sbitls"
)

// API URIs of the CAPIF core function (TS 29.222 table 5.1-2): CAPIF-1e
// serves the API invokers, the internal interface the API provider functions.
const (
	invokerManagementPrefix = "/api-invoker-management/v1"
	discoverPrefix          = "/service-apis/v1"
	securityPrefix          = "/capif-security/v1"
	publishPrefix           = "/published-apis/v1"
)

type ServerCcf interface {
	app.App
}

type Server struct {
	ServerCcf

	external       *http.Server
	internal       *http.Server
	externalRouter *gin.Engine
	internalRouter *gin.Engine
}

func NewServer(ccf ServerCcf) (*Server, error) {
	s := &Server{
		ServerCcf: ccf,
	}
	s.externalRouter = s.newExternalRouter()
	s.internalRouter = s.newInternalRouter()

	tlsConfig, err := s.TLSConfig()
	if err != nil {
		logger.InitLog.Errorf("Load the certificate of CAPIF-1e failed: %v", err)
		return nil, err
	}
	conf := s.Config().Configuration
	if conf.Internal.Tls() {
		// CAPIF-3/4 with the certificates of the operator (TS 33.122 cl. 6.6).
		if err = sbitls.Init(sbitls.Config{
			Certificate: conf.Internal.Certificate, Key: conf.Internal.Key, CA: conf.Internal.Ca, Logger: logger.SBILog,
		}); err != nil {
			logger.InitLog.Errorf("Load the certificate of the internal interface failed: %v", err)
			return nil, err
		}
	}
	s.external = &http.Server{
		Addr:              conf.Capif1e.Addr(),
		Handler:           s.externalRouter,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          log.New(logger.SBILog.WriterLevel(logrus.ErrorLevel), "CAPIF-1e: ", 0),
	}
	s.internal = &http.Server{
		Addr:              conf.Internal.Addr(),
		Handler:           s.internalRouter,
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          log.New(logger.SBILog.WriterLevel(logrus.ErrorLevel), "internal: ", 0),
	}
	if conf.Internal.Tls() {
		sbitls.ConfigureServer(s.internal)
	}
	return s, nil
}

// TLSConfig returns the TLS configuration of CAPIF-1e (TS 33.122 cl. 6.1 and
// 6.3.1.1; TS 29.222 cl. 7.3): TLS 1.3 and 1.2, with only ECDHE and AEAD
// cipher suites in TLS 1.2 (TS 33.210 cl. 6.2, the profile of TS 33.310
// Annex E), and HTTP/1.1 or HTTP/2 negotiated by ALPN (RFC 9113 cl. 3.2). The
// client certificate is verified when given: onboarding uses server-side TLS
// only, the other operations need the certificate issued at onboarding, and a
// certificate that the CCF revoked no longer opens a session (TS 33.310
// cl. 6.3.1).
func (s *Server) TLSConfig() (*tls.Config, error) {
	conf := s.Config().Configuration.Capif1e
	cert, err := tls.LoadX509KeyPair(conf.Certificate, conf.Key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    s.Context().CaPool(),
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		NextProtos: []string{"h2", "http/1.1"},
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) > 0 && s.Context().Revoked(state.PeerCertificates[0].SerialNumber) {
				return errors.New("revoked client certificate")
			}
			return nil
		},
	}, nil
}

// ExternalRouter returns the handler of CAPIF-1e (tests).
func (s *Server) ExternalRouter() http.Handler {
	return s.externalRouter
}

// InternalRouter returns the handler of the internal interface (tests).
func (s *Server) InternalRouter() http.Handler {
	return s.internalRouter
}

func (s *Server) newExternalRouter() *gin.Engine {
	router := newRouter([]string{"api-invoker-management", "service-apis", "capif-security"})
	router.POST(invokerManagementPrefix+"/onboardedInvokers", checkContentLength, s.HTTPOnboard)
	router.DELETE(invokerManagementPrefix+"/onboardedInvokers/:onboardingId", s.HTTPOffboard)
	router.GET(discoverPrefix+"/allServiceAPIs", s.HTTPDiscover)
	router.PUT(securityPrefix+"/trustedInvokers/:apiInvokerId", checkContentLength, s.HTTPObtainSecurityMethod)
	router.POST(securityPrefix+"/securities/:securityId/token", checkContentLength, s.HTTPObtainAuthorization)
	return router
}

func (s *Server) newInternalRouter() *gin.Engine {
	router := newRouter([]string{"published-apis", "capif-security"})
	router.POST(publishPrefix+"/:apfId/service-apis", checkContentLength, s.HTTPPublish)
	router.GET(publishPrefix+"/:apfId/service-apis", s.HTTPGetPublishedAPIs)
	router.GET(publishPrefix+"/:apfId/service-apis/:serviceApiId", s.HTTPGetPublishedAPI)
	router.DELETE(publishPrefix+"/:apfId/service-apis/:serviceApiId", s.HTTPUnpublish)
	router.GET(securityPrefix+"/trustedInvokers/:apiInvokerId", s.HTTPObtainAPIInvokerInfo)
	return router
}

// externalRoot is the apiRoot of CAPIF-1e, for the Location headers.
func (s *Server) externalRoot() string {
	return "https://" + s.Config().Configuration.Capif1e.Addr()
}

// internalRoot is the apiRoot of the internal interface.
func (s *Server) internalRoot() string {
	return s.Config().Configuration.Internal.ApiRoot()
}

func (s *Server) Run(_ context.Context, wg *sync.WaitGroup) error {
	wg.Add(2)
	go s.serve(wg, s.external, "CAPIF-1e", true)
	go s.serve(wg, s.internal, "internal", s.Config().Configuration.Internal.Tls())
	return nil
}

func (s *Server) serve(wg *sync.WaitGroup, srv *http.Server, name string, tls bool) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.SBILog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
			s.Terminate()
		}
		wg.Done()
	}()

	var err error
	if tls {
		logger.SBILog.Infof("Start %s server (https, listen on %s)", name, srv.Addr)
		err = srv.ListenAndServeTLS("", "")
	} else {
		logger.SBILog.Infof("Start %s server (http, listen on %s)", name, srv.Addr)
		err = srv.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		logger.SBILog.Errorf("Server on %s: %v", srv.Addr, err)
	}
	logger.SBILog.Infof("Server on %s stopped", srv.Addr)
}

func (s *Server) Shutdown() {
	const defaultShutdownTimeout time.Duration = 2 * time.Second

	for _, srv := range []*http.Server{s.external, s.internal} {
		if srv == nil {
			continue
		}
		toCtx, cancel := context.WithTimeout(context.Background(), defaultShutdownTimeout)
		if err := srv.Shutdown(toCtx); err != nil {
			logger.SBILog.Errorf("Could not close the server on %s: %v", srv.Addr, err)
		}
		cancel()
	}
}
