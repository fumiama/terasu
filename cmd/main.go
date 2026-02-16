// Package main provides the main entry point for terasu.
// It demonstrates basic Go usage of this library.
package main

import (
	"io"
	"net/http"
	"os"
	"strings"

	_ "github.com/fumiama/terasu/ext"
	"github.com/fumiama/terasu/http2"
	"github.com/sirupsen/logrus"
)

func main() {
	if len(os.Args) != 2 {
		logrus.Infoln("usage:", os.Args[0], "url")
		return
	}
	if !strings.HasPrefix(os.Args[1], "https://") {
		logrus.Errorln("invalid url")
		return
	}
	resp, err := http2.Get(os.Args[1])
	if err != nil {
		logrus.Errorln(err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logrus.Errorln("status code:", resp.StatusCode)
		return
	}

	_, err = io.Copy(os.Stdout, resp.Body)
	if err != nil {
		logrus.Errorln(err)
		return
	}
	logrus.Infoln("success.")
}
