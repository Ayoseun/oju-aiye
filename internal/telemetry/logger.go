package telemetry

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// LogLevel indicates severity.
type LogLevel string

const (
	LevelDebug LogLevel = "DEBUG"
	LevelInfo  LogLevel = "INFO"
	LevelWarn  LogLevel = "WARN"
	LevelError LogLevel = "ERROR"
)

// StructuredLog represents the canonical log entry specified in section 15.
type StructuredLog struct {
	Timestamp    string                 `json:"timestamp"`
	Level        LogLevel               `json:"level"`
	Message      string                 `json:"message"`
	JobID        string                 `json:"job_id,omitempty"`
	TaskID       string                 `json:"task_id,omitempty"`
	HypothesisID string                 `json:"hypothesis_id,omitempty"`
	AgentRole    string                 `json:"agent_role,omitempty"`
	ModelID      string                 `json:"model_id,omitempty"`
	TraceID      string                 `json:"trace_id,omitempty"`
	DurationMS   int64                  `json:"duration_ms,omitempty"`
	Status       string                 `json:"status,omitempty"`
	ErrorCode    string                 `json:"error_code,omitempty"`
	Fields       map[string]interface{} `json:"fields,omitempty"`
}

// Logger provides thread-safe structured logging.
type Logger struct {
	mu  sync.Mutex
	out io.Writer
}

var defaultLogger = &Logger{out: os.Stdout}

func SetDefaultLogger(l *Logger) {
	defaultLogger = l
}

func NewLogger(out io.Writer) *Logger {
	return &Logger{out: out}
}

func (l *Logger) Log(entry StructuredLog) {
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}

	bytes, err := json.Marshal(entry)
	if err != nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.out.Write(append(bytes, '\n'))
}

func Info(msg string, fields map[string]interface{}) {
	defaultLogger.Log(StructuredLog{
		Level:   LevelInfo,
		Message: msg,
		Fields:  fields,
	})
}

func Error(msg string, errCode string, fields map[string]interface{}) {
	defaultLogger.Log(StructuredLog{
		Level:     LevelError,
		Message:   msg,
		ErrorCode: errCode,
		Fields:    fields,
	})
}
