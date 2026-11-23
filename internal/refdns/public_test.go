// SPDX-License-Identifier: Apache-2.0

package refdns_test

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/home-mandate/relay-spec/internal/refdns"
)

const apex = "relay-test.example.net"

// public serves the zones homes.<apex> and tester.<apex> publicly on a loopback port.
func public(t *testing.T, rate float64, burst int) (*refdns.DNS, *refdns.Public) {
	t.Helper()
	d, err := refdns.New("homes."+apex, "tester."+apex)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	p, err := d.ServePublic(refdns.PublicConfig{
		Apex: apex, Listen: []string{"127.0.0.1:0"}, Rate: rate, Burst: burst,
		NSAddrs: []netip.Addr{netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("2001:db8::53")},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	d.Replace("x.homes."+apex, refdns.TypeCAA, refdns.CAA("x.homes."+apex, 300, 0, "issue", ";"))
	d.Replace("_acme-challenge.x.homes."+apex, refdns.TypeTXT, refdns.TXT("_acme-challenge.x.homes."+apex, 60, "value"))
	d.Replace("x.homes."+apex, refdns.TypeA, refdns.A("x.homes."+apex, 300, netip.MustParseAddr("127.0.0.1")))
	return d, p
}

func question(name string, typ dnsmessage.Type, edns bool) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 4711})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: typ, Class: dnsmessage.ClassINET})
	if edns {
		_ = b.StartAdditionals()
		var h dnsmessage.ResourceHeader
		_ = h.SetEDNS0(1232, dnsmessage.RCodeSuccess, false)
		_ = b.OPTResource(h, dnsmessage.OPTResource{})
	}
	out, _ := b.Finish()
	return out
}

func askUDP(t *testing.T, addr string, wire []byte) (dnsmessage.Message, bool) {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(500 * time.Millisecond))
	_, _ = c.Write(wire)
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return dnsmessage.Message{}, false
	}
	var m dnsmessage.Message
	if m.Unpack(buf[:n]) != nil {
		t.Fatal("no DNS message")
	}
	return m, true
}

func askTCP(t *testing.T, addr string, wire []byte) dnsmessage.Message {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Write(binary.BigEndian.AppendUint16(nil, uint16(len(wire))))
	_, _ = c.Write(wire)
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	if m.Unpack(buf) != nil {
		t.Fatal("no DNS message")
	}
	return m
}

// TestThePublicServerAnswersOnlyForItsZone: authoritative answers for the delegated zone and its
// names, no zone cut below it, no loopback address, no answer for anything else.
func TestThePublicServerAnswersOnlyForItsZone(t *testing.T) {
	_, p := public(t, 1000, 1000)
	for name, tt := range map[string]struct {
		name    string
		typ     dnsmessage.Type
		rcode   dnsmessage.RCode
		answers int
		aa      bool
	}{
		"SOA of the apex":            {apex, dnsmessage.TypeSOA, dnsmessage.RCodeSuccess, 1, true},
		"NS of the apex":             {apex, dnsmessage.TypeNS, dnsmessage.RCodeSuccess, 1, true},
		"A of the name server":       {"ns1." + apex, dnsmessage.TypeA, dnsmessage.RCodeSuccess, 1, true},
		"AAAA of the name server":    {"ns1." + apex, dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, 1, true},
		"CAA of a standard name":     {"X.HOMES." + apex, refdns.TypeCAA, dnsmessage.RCodeSuccess, 1, true},
		"challenge":                  {"_acme-challenge.x.homes." + apex, dnsmessage.TypeTXT, dnsmessage.RCodeSuccess, 1, true},
		"nothing at the apex":        {"homes." + apex, refdns.TypeCAA, dnsmessage.RCodeSuccess, 0, true},
		"no zone cut below the apex": {"homes." + apex, dnsmessage.TypeNS, dnsmessage.RCodeSuccess, 0, true},
		"no loopback address":        {"x.homes." + apex, dnsmessage.TypeA, dnsmessage.RCodeSuccess, 0, true},
		"no name":                    {"y.homes." + apex, dnsmessage.TypeTXT, dnsmessage.RCodeNameError, 0, true},
		"no name below the apex":     {"other." + apex, dnsmessage.TypeA, dnsmessage.RCodeNameError, 0, true},
		"another zone":               {"example.org", dnsmessage.TypeA, dnsmessage.RCodeRefused, 0, false},
	} {
		for _, transport := range []string{"udp", "tcp"} {
			var m dnsmessage.Message
			if transport == "udp" {
				var ok bool
				if m, ok = askUDP(t, p.Addr(), question(tt.name, tt.typ, true)); !ok {
					t.Fatalf("%s: no answer over UDP", name)
				}
			} else {
				m = askTCP(t, p.Addr(), question(tt.name, tt.typ, false))
			}
			if m.ID != 4711 || m.RCode != tt.rcode || len(m.Answers) != tt.answers || m.Authoritative != tt.aa || m.RecursionAvailable {
				t.Errorf("%s over %s: rcode %v, %d answers, aa %v", name, transport, m.RCode, len(m.Answers), m.Authoritative)
			}
			if tt.answers == 0 && tt.rcode != dnsmessage.RCodeRefused && (len(m.Authorities) != 1 || m.Authorities[0].Header.Type != dnsmessage.TypeSOA) {
				t.Errorf("%s over %s: no SOA in the authority section", name, transport)
			}
		}
	}
}

// TestThePublicServerLimitsEachSource: beyond the burst, queries of one source get no answer.
func TestThePublicServerLimitsEachSource(t *testing.T) {
	_, p := public(t, 0.001, 3)
	answered := 0
	for range 6 {
		if _, ok := askUDP(t, p.Addr(), question(apex, dnsmessage.TypeSOA, false)); ok {
			answered++
		}
	}
	if answered != 3 {
		t.Errorf("%d answered, want 3", answered)
	}
}

// TestALargeAnswerIsTruncatedOverUDP: an answer beyond 512 bytes without EDNS sets TC.
func TestALargeAnswerIsTruncatedOverUDP(t *testing.T) {
	d, p := public(t, 1000, 1000)
	name := "big.homes." + apex
	var rrs []dnsmessage.Resource
	for range 20 {
		rrs = append(rrs, refdns.TXT(name, 60, string(make([]byte, 100))))
	}
	d.Replace(name, refdns.TypeTXT, rrs...)
	m, ok := askUDP(t, p.Addr(), question(name, dnsmessage.TypeTXT, false))
	if !ok || !m.Truncated || len(m.Answers) != 0 {
		t.Errorf("truncated %v, %d answers", m.Truncated, len(m.Answers))
	}
	if m := askTCP(t, p.Addr(), question(name, dnsmessage.TypeTXT, false)); len(m.Answers) != 20 {
		t.Errorf("over TCP: %d answers", len(m.Answers))
	}
}

func TestPublicConfigIsChecked(t *testing.T) {
	d, err := refdns.New("homes." + apex)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ns := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	for name, cfg := range map[string]refdns.PublicConfig{
		"no apex":      {Listen: []string{"127.0.0.1:0"}, NSAddrs: ns},
		"zone outside": {Apex: "other.example", Listen: []string{"127.0.0.1:0"}, NSAddrs: ns},
		"no address":   {Apex: apex, Listen: []string{"127.0.0.1:0"}},
		"no listen":    {Apex: apex, NSAddrs: ns},
		"bad listen":   {Apex: apex, Listen: []string{"nope"}, NSAddrs: ns},
		"second bad":   {Apex: apex, Listen: []string{"127.0.0.1:0", "nope"}, NSAddrs: ns},
	} {
		if p, err := d.ServePublic(cfg); err == nil {
			p.Close()
			t.Errorf("%s: served", name)
		}
	}
}

// TestTCPConnectionsArePerSource: a source holds at most four connections at a time.
func TestTCPConnectionsArePerSource(t *testing.T) {
	_, p := public(t, 1000, 1000)
	var conns []net.Conn
	for range 6 {
		c, err := net.Dial("tcp", p.Addr())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	time.Sleep(100 * time.Millisecond)
	closed := 0
	for _, c := range conns {
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if _, err := c.Read(make([]byte, 1)); err == io.EOF {
			closed++
		}
		_ = c.Close()
	}
	if closed != 2 {
		t.Errorf("%d connections closed at once, want 2", closed)
	}
}

// TestASmallEDNSSizeIsHonoured: a client that advertises less than 1232 bytes gets at most 512.
func TestASmallEDNSSizeIsHonoured(t *testing.T) {
	d, p := public(t, 1000, 1000)
	name := "mid.homes." + apex
	var rrs []dnsmessage.Resource
	for range 6 {
		rrs = append(rrs, refdns.TXT(name, 60, string(make([]byte, 100))))
	}
	d.Replace(name, refdns.TypeTXT, rrs...)
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET})
	_ = b.StartAdditionals()
	var h dnsmessage.ResourceHeader
	_ = h.SetEDNS0(400, dnsmessage.RCodeSuccess, false)
	_ = b.OPTResource(h, dnsmessage.OPTResource{})
	wire, _ := b.Finish()
	if m, ok := askUDP(t, p.Addr(), wire); !ok || !m.Truncated {
		t.Errorf("an answer of about 700 bytes to a client of 400: truncated %v", m.Truncated)
	}
	if m, ok := askUDP(t, p.Addr(), question(name, dnsmessage.TypeTXT, true)); !ok || m.Truncated || len(m.Answers) != 6 {
		t.Errorf("to a client of 1232: truncated %v, %d answers", m.Truncated, len(m.Answers))
	}
}

// TestThePublicServerListensOnEveryAddress: next to a resolver on another loopback address, the
// view binds each given address by itself, over UDP and TCP.
func TestThePublicServerListensOnEveryAddress(t *testing.T) {
	stub, err := net.ListenPacket("udp", "127.0.0.53:0")
	if err != nil {
		t.Skip("no 127.0.0.53:", err)
	}
	defer stub.Close()
	port := stub.LocalAddr().(*net.UDPAddr).Port
	d, err := refdns.New("homes." + apex)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	listen := []string{net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), net.JoinHostPort("127.0.0.2", strconv.Itoa(port))}
	p, err := d.ServePublic(refdns.PublicConfig{Apex: apex, Listen: listen, NSAddrs: []netip.Addr{netip.MustParseAddr("192.0.2.53")}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, addr := range listen {
		if m, ok := askUDP(t, addr, question(apex, dnsmessage.TypeSOA, false)); !ok || len(m.Answers) != 1 {
			t.Errorf("%s over UDP: %v", addr, ok)
		}
		if m := askTCP(t, addr, question(apex, dnsmessage.TypeSOA, false)); len(m.Answers) != 1 {
			t.Errorf("%s over TCP: %d answers", addr, len(m.Answers))
		}
	}
}
