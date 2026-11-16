// SPDX-License-Identifier: Apache-2.0

package frames

import (
	"bytes"
	"testing"
	"time"
)

// FuzzBind feeds the first bytes of a data connection, which anyone who reaches the relay can
// send, to Bind (section 4.5). Whatever the bytes, a connection is bound only by an open token
// of its own installation, and only a token the relay knows is consumed.
func FuzzBind(f *testing.F) {
	own := bytes.Repeat([]byte{0x11}, TokenSize)
	other := bytes.Repeat([]byte{0x22}, TokenSize)
	used := bytes.Repeat([]byte{0x33}, TokenSize)
	frame := func(token []byte) []byte {
		return append([]byte{0, typeDataBind, 0, TokenSize}, token...)
	}
	for _, seed := range [][]byte{nil, frame(own), frame(other), frame(used), append(frame(own), 0), {0, typeDataBind, 0, TokenSize + 1}} {
		f.Add(seed)
	}
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	state := RelayState{
		Tokens: []Token{
			{Token: own, Installation: "home-a", State: Open},
			{Token: other, Installation: "home-b", State: Open},
			{Token: used, Installation: "home-a", State: Used},
		},
		ControlNotBefore: now,
	}
	conn := Connection{Installation: "home-a", NotBefore: now}
	f.Fuzz(func(t *testing.T, first []byte) {
		b := Bind(state, conn, first)
		if b.Bound && (len(b.Consumed) != 1 || !bytes.Equal(b.Consumed[0], own)) {
			t.Fatalf("bound without consuming exactly the open token of its installation: %+v", b)
		}
		for _, c := range b.Consumed {
			if !bytes.Equal(c, own) && !bytes.Equal(c, other) {
				t.Fatalf("consumed a token the relay did not hold or had used: %x", c)
			}
		}
		if b.Bound && !bytes.Equal(first, frame(own)) {
			t.Fatalf("bound by bytes that are not exactly the data-bind of the token: %x", first)
		}
	})
}
