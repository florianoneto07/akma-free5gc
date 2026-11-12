package sbi

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/logger"
	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/sbi/consumer"
	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/sbi/processor"
	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/pkg/app"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/openapi/sbitls"
	"github.com/free5gc/util/httpwrapper"
	logger_util "github.com/free5gc/util/logger"
)

type ServerAanf interface {
	app.App

	Consumer() *consumer.Consumer
	Processor() *processor.Processor
}

type Server struct {
	ServerAanf

	httpServer *http.Server
	router     *gin.Engine
}

func NewServer(aanf ServerAanf) (*Server, error) {
	s := &Server{
		ServerAanf: aanf,
	}

	s.router = newRouter(s)

	cfg := s.Config()
	bindAddr := cfg.GetSbiBindingAddr()
	logger.SBILog.Infof("Binding addr: [%s]", bindAddr)
	var err error
	if s.httpServer, err = httpwrapper.NewHttp2Server(bindAddr, "", s.router); err != nil {
		logger.InitLog.Errorf("Initialize HTTP server failed: %v", err)
		return nil, err
	}
	s.httpServer.ErrorLog = log.New(logger.SBILog.WriterLevel(logrus.ErrorLevel), "HTTP2: ", 0)

	return s, nil
}

// Router returns the HTTP handler of the SBI server (tests).
func (s *Server) Router() http.Handler {
	return s.router
}

func newRouter(s *Server) *gin.Engine {
	router := logger_util.NewGinWithLogrus(logger.GinLog)
	// A trailing slash is a different resource: answer 404 instead of a
	// redirection.
	router.RedirectTrailingSlash = false
	router.RedirectFixedPath = false
	router.HandleMethodNotAllowed = false
	// No proxy is trusted: the client address logged is the address of the
	// connection, as used by the AF policy.
	_ = router.SetTrustedProxies(nil)
	router.Use(s.sbiHeaders, recoverWithProblem())
	router.NoRoute(noRoute)

	s.applyAkmaRoutes(router)
	return router
}

func (s *Server) Run(ctx context.Context, wg *sync.WaitGroup) error {
	var err error
	_, s.Context().NfId, err = s.Consumer().RegisterNFInstance(ctx)
	if err != nil {
		logger.InitLog.Errorf("AANF register to NRF Error[%s]", err.Error())
	} else {
		// TS 29.510 cl. 5.2.2.3.2 (F29).
		go s.Consumer().RunHeartBeat(ctx)
	}

	wg.Add(1)
	go s.startServer(wg)

	return nil
}

// sbiHeaders puts in every response the headers of TS 29.500 that identify
// the AAnF: Server, which table 5.2.2.2-1 asks of the originator of an error
// response and allows in the others, and 3gpp-Sbi-NF-Peer-Info (cl.
// 5.2.3.2.21), with the NF instance of the consumer when known: the one of
// its client certificate or, without TLS, the one of the header of the
// request.
func (s *Server) sbiHeaders(c *gin.Context) {
	self := s.Context().NfId
	c.Header(openapi.HeaderServer, openapi.NfAgent(models.NrfNfManagementNfType_AANF, self))
	if info := openapi.NfPeerInfo(self, consumerInstance(c.Request)); info != "" {
		c.Header(openapi.HeaderNfPeerInfo, info)
	}
	// The NF type of the consumer, as it says (TS 29.500 table 5.2.2.2-1).
	logger.SBILog.Infof("%s %s, User-Agent %s, 3gpp-Sbi-NF-Peer-Info %s", c.Request.Method, c.Request.URL.Path,
		orNone(c.Request.UserAgent()), orNone(c.Request.Header.Get(openapi.HeaderNfPeerInfo)))
	c.Next()
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// consumerInstance returns the NF instance ID of the consumer of a request,
// empty when unknown.
func consumerInstance(r *http.Request) string {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		if id, err := sbitls.NfInstanceId(r.TLS.PeerCertificates[0]); err == nil {
			return id
		}
	}
	return openapi.PeerInfoSource(r.Header.Get(openapi.HeaderNfPeerInfo))
}

func (s *Server) Shutdown() {
	s.shutdownHttpServer()
}

func (s *Server) shutdownHttpServer() {
	const defaultShutdownTimeout time.Duration = 2 * time.Second

	if s.httpServer != nil {
		logger.SBILog.Infof("Stop SBI server (listen on %s)", s.httpServer.Addr)
		toCtx, cancel := context.WithTimeout(context.Background(), defaultShutdownTimeout)
		defer cancel()
		if err := s.httpServer.Shutdown(toCtx); err != nil {
			logger.SBILog.Errorf("Could not close SBI server: %#v", err)
		}
	}
}

func (s *Server) startServer(wg *sync.WaitGroup) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.SBILog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
			s.Terminate()
		}
		wg.Done()
	}()

	logger.SBILog.Infof("Start SBI server (listen on %s)", s.httpServer.Addr)

	var err error
	cfg := s.Config()
	scheme := cfg.GetSbiScheme()
	switch scheme {
	case "http":
		err = s.httpServer.ListenAndServe()
	case "https":
		sbitls.ConfigureServer(s.httpServer)
		err = s.httpServer.ListenAndServeTLS(
			cfg.GetCertPemPath(),
			cfg.GetCertKeyPath())
	default:
		err = fmt.Errorf("no support this scheme[%s]", scheme)
	}

	if err != nil && err != http.ErrServerClosed {
		logger.SBILog.Errorf("SBI server error: %v", err)
	}
	logger.SBILog.Infof("SBI server (listen on %s) stopped", s.httpServer.Addr)
}
