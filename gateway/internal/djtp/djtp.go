// Package ptp implements the DuckJump Transport Protocol spoken with duckjumpd.
// It mirrors duckjumpd/crates/duckjump-proto; see that crate for the spec.
package djtp

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	Version     = 1
	MaxFrameLen = 1 << 20

	KindControl byte = 0x01
	KindOutput  byte = 0x02
	KindInput   byte = 0x03
	// Graphical sessions: display operations (daemon -> gateway) and input
	// events (gateway -> daemon). Payload formats: duckjump-proto/src/gfx.rs.
	KindDisplay    byte = 0x04
	KindInputEvent byte = 0x05
)

type Frame struct {
	Kind    byte
	Payload []byte
}

func WriteFrame(w io.Writer, kind byte, payload []byte) error {
	n := len(payload) + 1
	if n > MaxFrameLen {
		return fmt.Errorf("ptp: frame too large (%d bytes)", n)
	}
	buf := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(buf, uint32(n))
	buf[4] = kind
	copy(buf[5:], payload)
	_, err := w.Write(buf)
	return err
}

func WriteControl(w io.Writer, c any) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return WriteFrame(w, KindControl, b)
}

func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return Frame{}, errors.New("ptp: empty frame")
	}
	if n > MaxFrameLen {
		return Frame{}, fmt.Errorf("ptp: frame too large (%d bytes)", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return Frame{}, err
	}
	return Frame{Kind: buf[0], Payload: buf[1:]}, nil
}

// Control is the union of all control messages. Type selects the variant.
type Control struct {
	Type string `json:"type"`

	// hello
	Version   int        `json:"version,omitempty"`
	Token     string     `json:"token,omitempty"`
	SessionID string     `json:"session_id,omitempty"`
	Protocol  string     `json:"protocol,omitempty"`
	Params    any        `json:"params,omitempty"`
	Recording *Recording `json:"recording,omitempty"`
	Relay     *Relay     `json:"relay,omitempty"`

	// ready
	HostKeyFingerprint *string `json:"host_key_fingerprint,omitempty"`

	// resize
	Cols int `json:"cols,omitempty"`
	Rows int `json:"rows,omitempty"`

	// close
	Reason *string `json:"reason,omitempty"`

	// exit
	Status *uint32 `json:"status,omitempty"`

	// clipboard
	Text string `json:"text,omitempty"`

	// error
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`

	// fs_list, fs_entries, fs_read, fs_meta, fs_write, fs_end, fs_done
	Path      string    `json:"path,omitempty"`
	Entries   []FsEntry `json:"entries,omitempty"`
	Size      uint64    `json:"size,omitempty"`
	Overwrite bool      `json:"overwrite,omitempty"`
	Bytes     uint64    `json:"bytes,omitempty"`
}

// FsEntry is one directory entry of a file session.
type FsEntry struct {
	Name  string  `json:"name"`
	Dir   bool    `json:"dir"`
	Link  bool    `json:"link"`
	Size  uint64  `json:"size"`
	MTime *uint32 `json:"mtime"`
	Mode  *uint32 `json:"mode"`
}

// Relay tells duckjumpd to reach the target through the gateway's edge relay
// instead of dialing it directly.
type Relay struct {
	Addr   string `json:"addr"`
	Ticket string `json:"ticket"`
	// TLSFingerprint: the relay listener speaks TLS with this certificate
	// ("SHA256:<hex>" of its DER); duckjumpd checks it before sending the ticket.
	TLSFingerprint string `json:"tls_fingerprint,omitempty"`
}

type Recording struct {
	Name         string `json:"name"`
	IncludeInput bool   `json:"include_input"`
}

type SSHParams struct {
	Host     string  `json:"host"`
	Port     int     `json:"port"`
	Username string  `json:"username"`
	Auth     SSHAuth `json:"auth"`
	HostKey  *string `json:"host_key,omitempty"`
	// TrustUnknown: with no HostKey, accept whatever key the server shows
	// (trust on first use). Otherwise duckjumpd stops before authenticating and
	// reports the key with error code host_key_unknown.
	TrustUnknown bool   `json:"trust_unknown,omitempty"`
	Term         string `json:"term,omitempty"`
	Cols         int    `json:"cols"`
	Rows         int    `json:"rows"`
}

type VNCParams struct {
	Host      string  `json:"host"`
	Port      int     `json:"port"`
	Username  string  `json:"username,omitempty"` // VeNCrypt Plain only
	Password  *string `json:"password,omitempty"`
	Exclusive bool    `json:"exclusive"`
	// Security: "any" (TLS when the server offers VeNCrypt, else what it
	// offers), or "tls" (refuse servers without VeNCrypt X.509).
	Security        string  `json:"security,omitempty"`
	CertFingerprint *string `json:"cert_fingerprint,omitempty"`
	TrustUnknown    bool    `json:"trust_unknown,omitempty"`
}

type RDPParams struct {
	Host            string  `json:"host"`
	Port            int     `json:"port"`
	Username        string  `json:"username"`
	Password        string  `json:"password"`
	Domain          string  `json:"domain,omitempty"`
	Security        string  `json:"security"` // any | nla | tls
	CertFingerprint *string `json:"cert_fingerprint,omitempty"`
	TrustUnknown    bool    `json:"trust_unknown,omitempty"`
	Width           int     `json:"width"`
	Height          int     `json:"height"`
}

type SSHAuth struct {
	Method     string  `json:"method"` // "password" | "private_key"
	Password   string  `json:"password,omitempty"`
	Key        string  `json:"key,omitempty"`
	Passphrase *string `json:"passphrase,omitempty"`
}

func DecodeControl(f Frame) (Control, error) {
	var c Control
	err := json.Unmarshal(f.Payload, &c)
	return c, err
}
