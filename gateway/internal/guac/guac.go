// Package guac implements the Apache Guacamole instruction format and the
// client side of the guacd handshake. It is the compatibility layer that lets
// the gateway route protocols duckjumpd does not implement yet (RDP, VNC) to a
// legacy guacd.
package guac

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxInstructionLen matches guacd's limit.
const MaxInstructionLen = 8192

var ErrMalformed = errors.New("guac: malformed instruction")

type Instruction struct {
	Opcode string
	Args   []string
}

func New(opcode string, args ...string) Instruction {
	return Instruction{Opcode: opcode, Args: args}
}

// String encodes the instruction. Element lengths count Unicode code points.
func (i Instruction) String() string {
	var b strings.Builder
	writeElem(&b, i.Opcode)
	for _, a := range i.Args {
		b.WriteByte(',')
		writeElem(&b, a)
	}
	b.WriteByte(';')
	return b.String()
}

func writeElem(b *strings.Builder, v string) {
	b.WriteString(strconv.Itoa(utf8.RuneCountInString(v)))
	b.WriteByte('.')
	b.WriteString(v)
}

type Reader struct {
	r *bufio.Reader
}

func NewReader(r io.Reader) *Reader { return &Reader{r: bufio.NewReader(r)} }

// Read returns the next instruction and its raw encoding.
func (r *Reader) Read() (Instruction, string, error) {
	var raw strings.Builder
	var elems []string
	for {
		lenStr, err := r.r.ReadString('.')
		if err != nil {
			return Instruction{}, "", err
		}
		raw.WriteString(lenStr)
		n, err := strconv.Atoi(lenStr[:len(lenStr)-1])
		if err != nil || n < 0 || n > MaxInstructionLen {
			return Instruction{}, "", ErrMalformed
		}
		var v strings.Builder
		for range n {
			c, _, err := r.r.ReadRune()
			if err != nil {
				return Instruction{}, "", err
			}
			v.WriteRune(c)
		}
		sep, err := r.r.ReadByte()
		if err != nil {
			return Instruction{}, "", err
		}
		raw.WriteString(v.String())
		raw.WriteByte(sep)
		if raw.Len() > MaxInstructionLen {
			return Instruction{}, "", ErrMalformed
		}
		elems = append(elems, v.String())
		switch sep {
		case ',':
		case ';':
			return Instruction{Opcode: elems[0], Args: elems[1:]}, raw.String(), nil
		default:
			return Instruction{}, "", ErrMalformed
		}
	}
}

// Handshake drives the client side of the guacd handshake on rw and returns
// the connection id from the "ready" instruction. params holds connection
// parameters by name; guacd's "args" reply decides their order.
func Handshake(rw io.ReadWriter, rd *Reader, protocol string, params map[string]string, width, height, dpi int) (string, error) {
	send := func(i Instruction) error {
		_, err := io.WriteString(rw, i.String())
		return err
	}
	if err := send(New("select", protocol)); err != nil {
		return "", err
	}
	args, _, err := rd.Read()
	if err != nil {
		return "", err
	}
	if args.Opcode != "args" {
		return "", fmt.Errorf("guac: expected args, got %q", args.Opcode)
	}

	values := make([]string, len(args.Args))
	for i, name := range args.Args {
		if strings.HasPrefix(name, "VERSION_") {
			values[i] = "VERSION_1_5_0"
			continue
		}
		values[i] = params[name]
	}
	for _, ins := range []Instruction{
		New("size", strconv.Itoa(width), strconv.Itoa(height), strconv.Itoa(dpi)),
		New("audio"),
		New("video"),
		New("image", "image/png", "image/jpeg", "image/webp"),
		New("timezone", "UTC"),
		New("connect", values...),
	} {
		if err := send(ins); err != nil {
			return "", err
		}
	}

	ready, _, err := rd.Read()
	if err != nil {
		return "", err
	}
	switch ready.Opcode {
	case "ready":
		if len(ready.Args) == 0 {
			return "", ErrMalformed
		}
		return ready.Args[0], nil
	case "error":
		return "", fmt.Errorf("guacd: %v", ready.Args)
	default:
		return "", fmt.Errorf("guac: expected ready, got %q", ready.Opcode)
	}
}
