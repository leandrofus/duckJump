package guac

import (
	"io"
	"net"
	"strings"
	"testing"
)

func TestEncodeCountsRunes(t *testing.T) {
	got := New("args", "VERSION_1_5_0", "año", "🥑").String()
	want := "4.args,13.VERSION_1_5_0,3.año,1.🥑;"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestReadRoundTrip(t *testing.T) {
	in := New("clipboard", "a,b;c.d", "duckjump 🥑", "")
	r := NewReader(strings.NewReader(in.String() + New("nop").String()))
	got, raw, err := r.Read()
	if err != nil || got.Opcode != in.Opcode || len(got.Args) != 3 || got.Args[1] != "duckjump 🥑" || raw != in.String() {
		t.Fatalf("got %+v %q %v", got, raw, err)
	}
	if got, _, _ := r.Read(); got.Opcode != "nop" {
		t.Fatalf("got %+v", got)
	}
	if _, _, err := r.Read(); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestHandshakeAgainstFakeGuacd(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		r := NewReader(server)
		if sel, _, _ := r.Read(); sel.Opcode != "select" || sel.Args[0] != "rdp" {
			t.Errorf("bad select %+v", sel)
			return
		}
		io.WriteString(server, New("args", "VERSION_1_5_0", "hostname", "port", "password").String())
		var connect Instruction
		for connect.Opcode != "connect" {
			connect, _, _ = r.Read()
		}
		want := []string{"VERSION_1_5_0", "10.0.0.9", "3389", ""}
		for i := range want {
			if connect.Args[i] != want[i] {
				t.Errorf("connect arg %d = %q want %q", i, connect.Args[i], want[i])
			}
		}
		io.WriteString(server, New("ready", "$abc").String())
	}()
	id, err := Handshake(client, NewReader(client), "rdp",
		map[string]string{"hostname": "10.0.0.9", "port": "3389"}, 1024, 768, 96)
	if err != nil || id != "$abc" {
		t.Fatalf("id=%q err=%v", id, err)
	}
}
