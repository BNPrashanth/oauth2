/*
Package configs implements configuration functions needed to run the application.
It contains the initialization functions to enable,
	Viper
	Uber-Zap-Custom-Logger
*/
package helpers

import (
	"fmt"

	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	// Log variable is a globally accessible variable which will be initialized when the InitializeZapCustomLogger function is executed successfully.
	Log *zap.Logger
)

/*
InitializeViper Funtion initializes viper to read configuration and/or environment variables in the application.
*/
func InitializeViper() {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()
	viper.SetConfigType("yml")

	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Error reading config file, %s", err)
	}
}

/*
InitializeZapCustomLogger Funtion initializes a logger using uber-go/zap package in the application.
*/
func InitializeZapCustomLogger() {
	conf := zap.Config{
		Encoding:    "json",
		Level:       zap.NewAtomicLevelAt(zapcore.InfoLevel),
		OutputPaths: []string{viper.GetString("logger-output-path"), "stdout"},
		EncoderConfig: zapcore.EncoderConfig{
			LevelKey:     "level",
			TimeKey:      "time",
			CallerKey:    "file",
			MessageKey:   "msg",
			EncodeLevel:  zapcore.LowercaseLevelEncoder,
			EncodeTime:   zapcore.ISO8601TimeEncoder,
			EncodeCaller: zapcore.ShortCallerEncoder,
		},
	}
	Log, _ = conf.Build()
	Log.Info("Logger Initialized..")
}
