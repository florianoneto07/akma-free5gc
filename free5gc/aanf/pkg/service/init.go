package service

import (
	"context"
	"io"
	"os"
	"runtime/debug"
	"sync"

	"github.com/sirupsen/logrus"

	aanf_context "github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/context"
	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/logger"
	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/sbi"
	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/sbi/consumer"
	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/internal/sbi/processor"
	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/pkg/app"
	"github.com/florianoneto07/akma-free5gc/free5gc/aanf/pkg/factory"
)

var AANF *AanfApp

var _ app.App = &AanfApp{}

type AanfApp struct {
	aanfCtx *aanf_context.AANFContext
	cfg     *factory.Config

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	sbiServer *sbi.Server
	consumer  *consumer.Consumer
	processor *processor.Processor
}

func NewApp(ctx context.Context, cfg *factory.Config, tlsKeyLogPath string) (*AanfApp, error) {
	aanf := &AanfApp{
		cfg: cfg,
	}
	aanf.SetLogEnable(cfg.GetLogEnable())
	aanf.SetLogLevel(cfg.GetLogLevel())
	aanf.SetReportCaller(cfg.GetLogReportCaller())

	if err := aanf_context.Init(cfg); err != nil {
		return nil, err
	}
	aanf.aanfCtx = aanf_context.GetSelf()

	var err error
	if aanf.processor, err = processor.NewProcessor(aanf); err != nil {
		return nil, err
	}
	if aanf.consumer, err = consumer.NewConsumer(aanf); err != nil {
		return nil, err
	}
	aanf.processor.Refresher = aanf.consumer

	aanf.ctx, aanf.cancel = context.WithCancel(ctx)

	if aanf.sbiServer, err = sbi.NewServer(aanf, tlsKeyLogPath); err != nil {
		return nil, err
	}

	AANF = aanf
	return aanf, nil
}

func (a *AanfApp) CancelContext() context.Context {
	return a.ctx
}

func (a *AanfApp) Consumer() *consumer.Consumer {
	return a.consumer
}

func (a *AanfApp) Processor() *processor.Processor {
	return a.processor
}

func (a *AanfApp) Context() *aanf_context.AANFContext {
	return a.aanfCtx
}

func (a *AanfApp) Config() *factory.Config {
	return a.cfg
}

func (a *AanfApp) SetLogEnable(enable bool) {
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

func (a *AanfApp) SetLogLevel(level string) {
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

func (a *AanfApp) SetReportCaller(reportCaller bool) {
	logger.MainLog.Infof("Report Caller is set to [%v]", reportCaller)
	if reportCaller == logger.Log.ReportCaller {
		return
	}

	a.Config().SetLogReportCaller(reportCaller)
	logger.Log.SetReportCaller(reportCaller)
}

func (a *AanfApp) Start() {
	logger.InitLog.Infoln("Server started")

	a.wg.Add(1)
	go a.listenShutdownEvent()

	if err := a.sbiServer.Run(a.ctx, &a.wg); err != nil {
		logger.MainLog.Fatalf("Run SBI server failed: %+v", err)
	}
	a.WaitRoutineStopped()
}

func (a *AanfApp) listenShutdownEvent() {
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

func (a *AanfApp) Terminate() {
	a.cancel()
}

func (a *AanfApp) terminateProcedure() {
	logger.MainLog.Infof("Terminating AANF...")
	a.CallServerStop()

	// deregister with NRF
	problemDetails, err := a.Consumer().SendDeregisterNFInstance()
	if problemDetails != nil {
		logger.MainLog.Errorf("Deregister NF instance Failed Problem[%+v]", problemDetails)
	} else if err != nil {
		logger.MainLog.Errorf("Deregister NF instance Error[%+v]", err)
	} else {
		logger.MainLog.Infof("Deregister from NRF successfully")
	}
	logger.MainLog.Infof("AANF SBI Server terminated")
}

func (a *AanfApp) CallServerStop() {
	if a.sbiServer != nil {
		a.sbiServer.Shutdown()
	}
}

func (a *AanfApp) WaitRoutineStopped() {
	a.wg.Wait()
	logger.MainLog.Infof("AANF App is terminated")
}
