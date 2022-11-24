package main

import (
	"os"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/rifflock/lfshook"
	"github.com/sirupsen/logrus"
)
var log *localLog


func NewLogger(path string) *localLog {
	if log != nil {
		return log
	}

	lvl, ok := os.LookupEnv("LOG_LEVEL")
	// LOG_LEVEL not set, let's default to debug
	if !ok {
		lvl = "debug"
	}

	ll, err := logrus.ParseLevel(lvl)
	if err != nil {
		ll = logrus.DebugLevel
	}

	pathMap := lfshook.PathMap{
		logrus.InfoLevel:  path,
		logrus.ErrorLevel: path,
		logrus.DebugLevel: path,
		logrus.FatalLevel: path,
		logrus.WarnLevel:  path,
	}

	logging := logrus.New()
	logging.SetLevel(ll)
	logging.Hooks.Add(lfshook.NewHook(
		pathMap,
		&logrus.JSONFormatter{},
	))
	log = &localLog{mylogrus:  *logging}
	core.SetLogger(log)
	return log
}


type localLog struct{ mylogrus logrus.Logger }

var logLevelMap = map[core.LogLevel]logrus.Level{
	core.LevelDebug: logrus.DebugLevel,
	core.LevelError: logrus.ErrorLevel,
	core.LevelInfo:  logrus.InfoLevel,
	core.LevelWarn:  logrus.WarnLevel,
}

var reverseLogLevelMap = map[logrus.Level]core.LogLevel{
	logrus.DebugLevel: core.LevelDebug,
	logrus.ErrorLevel: core.LevelError,
	logrus.InfoLevel:  core.LevelInfo,
	logrus.WarnLevel:  core.LevelWarn,
}

func (lg localLog) Log(level core.LogLevel, format string, inserts ...interface{}) {
	lg.mylogrus.Log(logLevelMap[level], format, inserts)
}

func (lg localLog) Error(format string, inserts ...interface{}) {
	lg.mylogrus.Error(format, inserts)
}
func (lg localLog) Panic(args ...interface{})  {
	lg.mylogrus.Panic(args...)
}


func (lg localLog) Warn(format string, inserts ...interface{}) {
	lg.mylogrus.Warn(format, inserts)
}

func (lg localLog) Info(format string, inserts ...interface{}) {
	lg.mylogrus.Info(format, inserts)
}

func (lg localLog) Debug(format string, inserts ...interface{}) {
	lg.mylogrus.Debug(format, inserts)
}

func (lg localLog) Fatal(args ...interface{}) {
	lg.mylogrus.Fatal(args...)
}

func (lg localLog) SetLogLevel(level core.LogLevel) {
	lg.mylogrus.SetLevel(logLevelMap[level])
}

func (lg localLog) GetLogLevel() core.LogLevel {
	return reverseLogLevelMap[lg.mylogrus.GetLevel()]

}

func (lg localLog) IsLogLevelEnabled(level core.LogLevel) bool {
	return lg.mylogrus.IsLevelEnabled(logLevelMap[level])
}
