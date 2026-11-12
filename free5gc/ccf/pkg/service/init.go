package service

import (
	"context"
	"io"
	"os"
	"runtime/debug"
	"sync"

	"github.com/sirupsen/logrus"

	ccf_context "github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/context"
	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/logger"
	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/internal/sbi"
	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/pkg/app"
	"github.com/florianoneto07/akma-free5gc/free5gc/ccf/pkg/factory"
)

var CCF *CcfApp

var _ app.App = &CcfApp{}

type CcfApp struct {
	ccfCtx *ccf_context.CCFContext
	cfg    *factory.Config

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	sbiServer *sbi.Server
}

func NewApp(ctx context.Context, cfg *factory.Config) (*CcfApp, error) {
	ccf := &CcfApp{
		cfg: cfg,
	}
	ccf.SetLogEnable(cfg.GetLogEnable())
	ccf.SetLogLevel(cfg.GetLogLevel())
	ccf.SetReportCaller(cfg.GetLogReportCaller())

	if err := ccf_context.Init(cfg); err != nil {
		return nil, err
	}
	ccf.ccfCtx = ccf_context.GetSelf()

	ccf.ctx, ccf.cancel = context.WithCancel(ctx)

	var err error
	if ccf.sbiServer, err = sbi.NewServer(ccf); err != nil {
		return nil, err
	}

	CCF = ccf
	return ccf, nil
}

func (a *CcfApp) Context() *ccf_context.CCFContext {
	return a.ccfCtx
}

func (a *CcfApp) Config() *factory.Config {
	return a.cfg
}

func (a *CcfApp) SetLogEnable(enable bool) {
	logger.MainLog.Infof("Log enable is set to [%v]", enable)
	if enable && logger.Log.Out == os.Stderr {
		return
	} else if !enable && logger.Log.Out == io.Discard {
		return
	}

	a.Config().SetLogEnable(enable)
	if enable {
		logger.Log.SetOutput(os.Stderr)
	} else {
		logger.Log.SetOutput(io.Discard)
	}
}

func (a *CcfApp) SetLogLevel(level string) {
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		logger.MainLog.Warnf("Log level [%s] is invalid", level)
		return
	}

	logger.MainLog.Infof("Log level is set to [%s]", level)
	if lvl == logger.Log.GetLevel() {
		return
	}

	a.Config().SetLogLevel(level)
	logger.Log.SetLevel(lvl)
}

func (a *CcfApp) SetReportCaller(reportCaller bool) {
	logger.MainLog.Infof("Report Caller is set to [%v]", reportCaller)
	if reportCaller == logger.Log.ReportCaller {
		return
	}

	a.Config().SetLogReportCaller(reportCaller)
	logger.Log.SetReportCaller(reportCaller)
}

func (a *CcfApp) Start() {
	logger.InitLog.Infoln("Server started")

	a.wg.Add(1)
	go a.listenShutdownEvent()
	go a.ccfCtx.RunCrl(a.ctx)

	if err := a.sbiServer.Run(a.ctx, &a.wg); err != nil {
		logger.MainLog.Fatalf("Run servers failed: %+v", err)
	}
	a.WaitRoutineStopped()
}

func (a *CcfApp) listenShutdownEvent() {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.MainLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
		a.wg.Done()
	}()

	<-a.ctx.Done()
	a.terminateProcedure()
}

func (a *CcfApp) Terminate() {
	a.cancel()
}

func (a *CcfApp) terminateProcedure() {
	logger.MainLog.Infof("Terminating CCF...")
	a.CallServerStop()
	logger.MainLog.Infof("CCF servers terminated")
}

func (a *CcfApp) CallServerStop() {
	if a.sbiServer != nil {
		a.sbiServer.Shutdown()
	}
}

func (a *CcfApp) WaitRoutineStopped() {
	a.wg.Wait()
	logger.MainLog.Infof("CCF App is terminated")
}
