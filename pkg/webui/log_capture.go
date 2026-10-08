package webui

import (
	"io"
	"log"
	"os"
	"strings"
	"sync"
)

var (
	logMu        sync.Mutex
	activeTarget *runState
)

type logForwarder struct {
	orig io.Writer
}

func (f logForwarder) Write(p []byte) (int, error) {

	n, err := f.orig.Write(p)

	logMu.Lock()
	target := activeTarget
	logMu.Unlock()
	if target != nil {
		line := strings.TrimRight(string(p), "\r\n")
		if line != "" {
			target.log(line)
		}
	}
	return n, err
}

type logCapture struct {
	prev   io.Writer
	target *runState
}

func newLogCapture(st *runState) *logCapture {
	logMu.Lock()
	activeTarget = st
	logMu.Unlock()
	prev := log.Writer()
	log.SetOutput(logForwarder{orig: prev})
	return &logCapture{prev: prev, target: st}
}

func (l *logCapture) Restore() {
	logMu.Lock()
	if activeTarget == l.target {
		activeTarget = nil
	}
	logMu.Unlock()
	log.SetOutput(l.prev)
	_ = os.Stdout
}
