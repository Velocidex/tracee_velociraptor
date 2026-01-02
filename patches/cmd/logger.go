package main

import (
	"fmt"
	"log"
	"os"
)

type Logger struct {
	log *log.Logger
}

func NewLogger() *Logger {
	return &Logger{
		log: log.New(os.Stderr, "", log.LstdFlags|log.LUTC),
	}
}

func (self Logger) Log(format string, a ...interface{}) {
	self.log.Print(fmt.Sprintf(format, a...))
}

func (self Logger) Error(format string, a ...interface{}) {
	self.Log("Error: "+format, a...)
}

func (self Logger) Warn(format string, a ...interface{}) {
	self.Log("Warn: "+format, a...)
}

func (self Logger) Debug(format string, a ...interface{}) {
	self.Log("Debug: "+format, a...)
}
