package ext

import (
	"os"
	"plugin"

	"github.com/sirupsen/logrus"
)

const (
	TRSPluginFile = "./terasu.plugin.so"
)

func init() {
	if _, err := os.Stat(TRSPluginFile); err != nil {
		return
	}
	_, err := plugin.Open(TRSPluginFile)
	if err != nil {
		logrus.Warnln("[terasu.plugin] load", TRSPluginFile, "err:", err)
		logrus.Warnln("[terasu.plugin] hint: ensure the main binary and plugin are built with identical flags (e.g. both use -trimpath -ldflags=\"-s -w\"), and avoid using 'go run'")
		return
	}
}
