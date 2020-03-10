package shadowsocks

import (
	"log"
	"os"
)

var Debug DebugLog

type DebugLog bool
var dbgLog = log.New(os.Stdout, "[DEBUG] ", log.Ltime)
func (d DebugLog) Printf(format string, args ...interface{}) {
	if d {
		dbgLog.Printf(format, args...)
	}
}
func (d DebugLog) Println(args ...interface{}) {
	if d {
		dbgLog.Println(args...)
	}
}
