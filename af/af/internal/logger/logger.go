// Package logger provides the log entries of the AF, in the format of the
// free5GC network functions ("[INFO][AF][UA] ...").
//
// Log entries never carry key material: K_AF is held as kdf.Key, which
// prints as "[256-bit key]", and the Digest password is never logged.
package logger

import (
	"github.com/sirupsen/logrus"

	logger_util "github.com/free5gc/util/logger"
)

var (
	Log         *logrus.Logger
	MainLog     *logrus.Entry
	CfgLog      *logrus.Entry
	UaLog       *logrus.Entry
	ConsumerLog *logrus.Entry
)

func init() {
	Log = logger_util.New([]string{logger_util.FieldNF, logger_util.FieldCategory})
	nf := Log.WithField(logger_util.FieldNF, "AF")
	MainLog = nf.WithField(logger_util.FieldCategory, "Main")
	CfgLog = nf.WithField(logger_util.FieldCategory, "CFG")
	UaLog = nf.WithField(logger_util.FieldCategory, "UA")
	ConsumerLog = nf.WithField(logger_util.FieldCategory, "Consumer")
}
