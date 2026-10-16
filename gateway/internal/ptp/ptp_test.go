package ptp

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteControl(&buf, Control{Type: "resize", Cols: 80, Rows: 24}); err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(&buf, KindInput, []byte("ls\r")); err != nil {
		t.Fatal(err)
	}
	f, err := ReadFrame(&buf)
	if err != nil || f.Kind != KindControl {
		t.Fatalf("got %v %v", f, err)
	}
	c, err := DecodeControl(f)
	if err != nil || c.Type != "resize" || c.Cols != 80 || c.Rows != 24 {
		t.Fatalf("got %+v %v", c, err)
	}
	f, err = ReadFrame(&buf)
	if err != nil || f.Kind != KindInput || string(f.Payload) != "ls\r" {
		t.Fatalf("got %v %v", f, err)
	}
}

// Must match the byte layout produced by the Rust FrameCodec.
func TestWireLayout(t *testing.T) {
	var buf bytes.Buffer
	WriteFrame(&buf, KindOutput, []byte("hi"))
	want := []byte{0, 0, 0, 3, 0x02, 'h', 'i'}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("got %v want %v", buf.Bytes(), want)
	}
}
