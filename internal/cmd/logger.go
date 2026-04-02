package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

const (
	LevelTrace slog.Level = -8
	LevelFatal slog.Level = 12
	LevelPanic slog.Level = 16
)

func newLogger(level slog.Level) logger.ContextLogger {
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
			if attr.Key != slog.LevelKey {
				return attr
			}
			attrLevel := attr.Value.Any().(slog.Level)
			switch {
			case attrLevel < slog.LevelDebug:
				attr.Value = slog.StringValue("TRACE")
			case attrLevel >= LevelPanic:
				attr.Value = slog.StringValue("PANIC")
			case attrLevel >= LevelFatal:
				attr.Value = slog.StringValue("FATAL")
			}
			return attr
		},
	})
	return &slogLogger{logger: slog.New(handler)}
}

func parseLogLevel(name string) (slog.Level, error) {
	switch name {
	case "trace":
		return LevelTrace, nil
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, E.New("unknown log level: ", name)
	}
}

type slogLogger struct {
	logger *slog.Logger
}

func (l *slogLogger) Trace(args ...any) {
	l.logger.Log(context.Background(), LevelTrace, fmt.Sprint(args...))
}

func (l *slogLogger) Debug(args ...any) {
	l.logger.Debug(fmt.Sprint(args...))
}

func (l *slogLogger) Info(args ...any) {
	l.logger.Info(fmt.Sprint(args...))
}

func (l *slogLogger) Warn(args ...any) {
	l.logger.Warn(fmt.Sprint(args...))
}

func (l *slogLogger) Error(args ...any) {
	l.logger.Error(fmt.Sprint(args...))
}

func (l *slogLogger) Fatal(args ...any) {
	l.logger.Log(context.Background(), LevelFatal, fmt.Sprint(args...))
	os.Exit(1)
}

func (l *slogLogger) Panic(args ...any) {
	message := fmt.Sprint(args...)
	l.logger.Log(context.Background(), LevelPanic, message)
	panic(message)
}

func (l *slogLogger) TraceContext(ctx context.Context, args ...any) {
	l.logger.Log(ctx, LevelTrace, fmt.Sprint(args...))
}

func (l *slogLogger) DebugContext(ctx context.Context, args ...any) {
	l.logger.DebugContext(ctx, fmt.Sprint(args...))
}

func (l *slogLogger) InfoContext(ctx context.Context, args ...any) {
	l.logger.InfoContext(ctx, fmt.Sprint(args...))
}

func (l *slogLogger) WarnContext(ctx context.Context, args ...any) {
	l.logger.WarnContext(ctx, fmt.Sprint(args...))
}

func (l *slogLogger) ErrorContext(ctx context.Context, args ...any) {
	l.logger.ErrorContext(ctx, fmt.Sprint(args...))
}

func (l *slogLogger) FatalContext(ctx context.Context, args ...any) {
	l.logger.Log(ctx, LevelFatal, fmt.Sprint(args...))
	os.Exit(1)
}

func (l *slogLogger) PanicContext(ctx context.Context, args ...any) {
	message := fmt.Sprint(args...)
	l.logger.Log(ctx, LevelPanic, message)
	panic(message)
}
