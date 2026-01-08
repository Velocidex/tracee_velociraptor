package manager

type Logger interface {
	Log(format string, a ...interface{})
	Error(format string, a ...interface{})
	Warn(format string, a ...interface{})
	Debug(format string, a ...interface{})
}
