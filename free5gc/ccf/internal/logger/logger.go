package logger

import (
	"github.com/sirupsen/logrus"

	logger_util "github.com/free5gc/util/logger"
)

// Log entries never carry access tokens, onboarding credentials, onboarding
// secrets or private keys. The identifiers of API invokers and API provider
// functions are logged at info level.
var (
	Log      *logrus.Logger
	NfLog    *logrus.Entry
	MainLog  *logrus.Entry
	InitLog  *logrus.Entry
	CfgLog   *logrus.Entry
	CtxLog   *logrus.Entry
	SBILog   *logrus.Entry
	GinLog   *logrus.Entry
	CapifLog *logrus.Entry
	UtilLog  *logrus.Entry
)

func init() {
	fieldsOrder := []string{
		logger_util.FieldNF,
		logger_util.FieldCategory,
	}

	Log = logger_util.New(fieldsOrder)
	NfLog = Log.WithField(logger_util.FieldNF, "CCF")
	MainLog = NfLog.WithField(logger_util.FieldCategory, "Main")
	InitLog = NfLog.WithField(logger_util.FieldCategory, "Init")
	CfgLog = NfLog.WithField(logger_util.FieldCategory, "CFG")
	CtxLog = NfLog.WithField(logger_util.FieldCategory, "CTX")
	SBILog = NfLog.WithField(logger_util.FieldCategory, "SBI")
	GinLog = NfLog.WithField(logger_util.FieldCategory, "GIN")
	CapifLog = NfLog.WithField(logger_util.FieldCategory, "CAPIF")
	UtilLog = NfLog.WithField(logger_util.FieldCategory, "Util")
}
