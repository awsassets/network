package configure

import (
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/mattn/go-colorable"
	"github.com/rifflock/lfshook"
	"github.com/sirupsen/logrus"
)

func init() {
	log.SetOutput(io.Discard)
}

func initLogging(logs, name, level string, file bool) {
	formatter := &logrus.TextFormatter{
		ForceColors:  true,
		PadLevelText: true,
	}

	logrus.SetFormatter(formatter)

	if lvl, err := logrus.ParseLevel(level); err == nil {
		logrus.SetLevel(lvl)
		if lvl == logrus.DebugLevel {
			logrus.SetReportCaller(true)
		}
	}

	logrus.SetOutput(colorable.NewColorableStdout())

	if file {
		if err := os.MkdirAll(path.Join(logs, name), 0700); err == nil {
			file := fmt.Sprintf("%s.log", time.Now().Format(time.RFC3339))
			if runtime.GOOS == "windows" {
				file = strings.ReplaceAll(file, ":", ".")
			}
			logrus.AddHook(lfshook.NewHook(path.Join(logs, name, file), &logrus.TextFormatter{
				DisableColors: true,
				PadLevelText:  true,
				ForceQuote:    true,
			}))
		} else {
			logrus.Warn("Not logging to file: ", err)
		}
	}
}
