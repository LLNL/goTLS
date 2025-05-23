// Copyright © 2025 Lawrence Livermore National Security, LLC
// SPDX-License-Identifier: MIT
// See top-level LICENSE file for details.

package conhandler

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"
)

// ConsoleHandler automatically outputs Errors to Stderr and everything else to Stdout
type ConsoleHandler struct {
	goas   []groupOrAttrs
	opts   Options
	mu     *sync.Mutex
	writer io.Writer
}

type Options struct {
	// Level reports the minimum level to log. Levels with lower levels are discarded. Uses slog.LevelInfo by default.
	Level slog.Leveler

	// RemoveTime is a boolean setting to hide the time output from the beginning
	RemoveTime bool

	// RemoveInfoLabel is a boolean setting to overwrite the "INFO " label with spaces, if desired. In combination with
	// RemoveInfoLabel this will better simulate normal console output from a program.
	RemoveInfoLabel bool
}

// groupOrAttrs holds either a group name or a list of slog.Attrs.
type groupOrAttrs struct {
	group string      // group name if non-empty
	attrs []slog.Attr // attrs if non-empty
}

func NewConsoleHandler(writer io.Writer, opts *Options) *ConsoleHandler {
	h := &ConsoleHandler{
		writer: writer,
		mu:     &sync.Mutex{},
	}
	if opts != nil {
		h.opts = *opts
	}
	if h.opts.Level == nil {
		h.opts.Level = slog.LevelInfo
	}

	return h
}

func (h *ConsoleHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.opts.Level.Level()
}

func (h *ConsoleHandler) Handle(_ context.Context, r slog.Record) error {
	buf := make([]byte, 0, 1024)

	// output timestamp
	if !h.opts.RemoveTime && !r.Time.IsZero() {
		buf = h.appendAttr(buf, slog.Time(slog.TimeKey, r.Time))
	}

	// save configured writer
	writer := h.writer

	// output log level
	if h.opts.RemoveInfoLabel && r.Level == slog.LevelInfo {
		// output spaces instead of Info label
		buf = fmt.Appendf(buf, "%*s", 5, "")
	} else {
		switch {
		case r.Level < slog.LevelInfo:
			//TODO: if !noColor
			buf = fmt.Appendf(buf, "\u001b[2m")
			buf = fmt.Appendf(buf, "DEBUG")
			//TODO: if !noColor
			buf = fmt.Appendf(buf, "\u001b[0m")
		case r.Level < slog.LevelWarn:
			//TODO: if !noColor
			buf = fmt.Appendf(buf, "\u001b[92m")
			buf = fmt.Appendf(buf, "INFO ")
			//TODO: if !noColor
			buf = fmt.Appendf(buf, "\u001b[0m")
		case r.Level < slog.LevelError:
			//buf.WriteStringIf(!h.noColor, ansiBrightYellow)
			buf = fmt.Appendf(buf, "WARN ")
			//buf.WriteStringIf(!h.noColor, ansiReset)
		default:
			//TODO: if !noColor
			buf = fmt.Appendf(buf, "\u001b[91m")

			// redirect to Stderr
			h.writer = os.Stderr

			buf = fmt.Appendf(buf, "ERROR")
			//TODO: if !noColor
			buf = fmt.Appendf(buf, "\u001b[0m")
		}
	}

	// output message
	buf = fmt.Appendf(buf, " %s", r.Message)

	// Handle state from WithGroup and WithAttrs.
	goas := h.goas
	if r.NumAttrs() == 0 {
		// if the record has no Attrs, remove groups at the end of the list; they are empty.
		for len(goas) > 0 && goas[len(goas)-1].group != "" {
			goas = goas[:len(goas)-1]
		}
	}
	for _, goa := range goas {
		for _, a := range goa.attrs {
			buf = h.appendAttr(buf, a)
		}
	}

	// output attributes
	r.Attrs(func(a slog.Attr) bool {
		buf = h.appendAttr(buf, a)
		return true
	})

	// output newline
	buf = fmt.Appendf(buf, "\n")

	// write to writer
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.writer.Write(buf)

	if r.Level == slog.LevelError {
		// redirect to Stdout
		h.writer = writer
	}

	return err
}

func (h *ConsoleHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	return h.withGroupOrAttrs(groupOrAttrs{attrs: attrs})
}

func (h *ConsoleHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return h.withGroupOrAttrs(groupOrAttrs{group: name})
}

func (h *ConsoleHandler) appendAttr(buf []byte, a slog.Attr) []byte {
	// resolve attribute's value
	a.Value = a.Value.Resolve()

	// ignore empty attribute according to handler rules
	if a.Equal(slog.Attr{}) {
		return buf
	}

	//TODO: if !noColor
	buf = fmt.Appendf(buf, "\u001b[2m")

	switch a.Value.Kind() {
	case slog.KindString:
		// quote string values to make them easy to parse
		buf = fmt.Appendf(buf, " %s=\"", a.Key)
		//TODO: if !noColor
		buf = fmt.Appendf(buf, "\u001b[22m")
		buf = fmt.Appendf(buf, "%s", a.Value.String())
		//TODO: if !noColor
		buf = fmt.Appendf(buf, "\u001b[2m")
		buf = fmt.Appendf(buf, "\"")
	case slog.KindTime:
		// write times in a standard way, without the monotonic time.
		buf = fmt.Appendf(buf, " %s=", a.Key)
		//TODO: if !noColor
		buf = fmt.Appendf(buf, "\u001b[22m")
		buf = fmt.Appendf(buf, "%s", a.Value.Time().Format(time.RFC3339))
	case slog.KindGroup:
		attrs := a.Value.Group()
		// ignore empty groups.
		if len(attrs) == 0 {
			//TODO: if !noColor
			buf = fmt.Appendf(buf, "\u001b[22m")
			return buf
		}
		for _, ga := range attrs {
			// if the key is non-empty, prefix the remaining attributes with it
			if a.Key != "" {
				ga.Key = fmt.Sprintf("%s.%s", a.Key, ga.Key)
			}
			buf = h.appendAttr(buf, ga)
		}
	default:
		buf = fmt.Appendf(buf, " %s=", a.Key)
		//TODO: if !noColor
		buf = fmt.Appendf(buf, "\u001b[22m")
		buf = fmt.Appendf(buf, "%s", a.Value)
	}
	//TODO: if !noColor
	buf = fmt.Appendf(buf, "\u001b[22m")

	return buf
}

func (h *ConsoleHandler) withGroupOrAttrs(goa groupOrAttrs) *ConsoleHandler {
	h2 := *h
	h2.goas = make([]groupOrAttrs, len(h.goas)+1)
	copy(h2.goas, h.goas)
	h2.goas[len(h2.goas)-1] = goa
	return &h2
}
