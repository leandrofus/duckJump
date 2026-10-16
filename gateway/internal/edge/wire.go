// Package edge implements edge agents: an agent inside a closed network keeps
// an outbound WebSocket to the gateway, multiplexed with yamux, and the
// gateway opens streams back through it to reach hosts in that network.
//
// Per stream, the gateway sends one JSON line (dialRequest) and the agent
// answers one line: "ok" or "err <reason>". After that the stream carries the
// raw TCP bytes.
package edge

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const maxLine = 4096

type dialRequest struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Session string `json:"session"`
}

func writeLine(w io.Writer, s string) error {
	_, err := io.WriteString(w, s+"\n")
	return err
}

func writeJSONLine(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// readLine reads up to '\n' one byte at a time: the bytes after the line
// belong to the tunneled protocol (an SSH banner arrives right after "ok"),
// so nothing past it may be buffered.
func readLine(r io.Reader) (string, error) {
	var b strings.Builder
	var c [1]byte
	for b.Len() < maxLine {
		if _, err := io.ReadFull(r, c[:]); err != nil {
			return "", err
		}
		if c[0] == '\n' {
			return b.String(), nil
		}
		b.WriteByte(c[0])
	}
	return "", errors.New("edge: line too long")
}

// readStatus parses an "ok" / "err <reason>" line.
func readStatus(r io.Reader) error {
	line, err := readLine(r)
	if err != nil {
		return err
	}
	if line == "ok" {
		return nil
	}
	return errors.New(strings.TrimPrefix(line, "err "))
}
