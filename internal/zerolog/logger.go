package zerolog

import (
	"fmt"
	"io"
)

type Logger struct{ w io.Writer }

func New(w io.Writer) Logger { return Logger{w: w} }

func (l Logger) Error() *Event { return &Event{w: l.w} }

type Event struct{ w io.Writer }

func (e *Event) Msgf(format string, args ...interface{}) {
	fmt.Fprintf(e.w, format+"\n", args...)
}
