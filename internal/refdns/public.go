// SPDX-License-Identifier: Apache-2.0

package refdns

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Defaults and limits of the public server.
const (
	defaultRate    = 20
	defaultBurst   = 40
	maxTCPConns    = 32
	maxTCPPerSrc   = 4
	maxTCPQueries  = 8
	globalRate     = 500
	globalBurst    = 1000
	tcpDeadline    = 5 * time.Second
	maxQueryBytes  = 4096
	udpPlainBytes  = 512
	udpEDNSBytes   = 1232
	maxBuckets     = 10000
	publicTTL      = 3600
	soaRetry       = 600
	soaExpire      = 86400
	soaMinimum     = 60
	prefixBitsIPv6 = 64
	listenAttempts = 10
)

// PublicConfig configures the public view of a DNS (Public).
type PublicConfig struct {
	// Apex is the delegated zone; every zone of the DNS must lie below it.
	Apex string
	// Listen are the addresses for UDP and TCP, such as "192.0.2.53:53"; each is bound by itself,
	// so that the view runs next to a resolver on a loopback address of the same port.
	Listen []string
	// NSAddrs are the addresses of the name server ns1.<Apex>, as the glue of the delegation has them.
	NSAddrs []netip.Addr
	// Rate and Burst limit the queries of one source (an IPv4 address or an IPv6 /64) per
	// second; zero means 20 and 40.
	Rate  float64
	Burst int
}

// Public is the public, authoritative view of the zones of a DNS under a delegated apex: what
// a CA sees during a live run. It answers only for the apex and below, from the first name
// server of each zone, without zone cuts below the apex and without addresses that are not
// globally reachable, and limits each source.
type Public struct {
	d   *DNS
	cfg PublicConfig
	udp []*net.UDPConn
	tcp []net.Listener
	lim *limiter
	sem chan struct{}
	wg  sync.WaitGroup

	connMu sync.Mutex
	conns  map[netip.Prefix]int
}

// ServePublic starts the public view.
func (d *DNS) ServePublic(cfg PublicConfig) (*Public, error) {
	cfg.Apex = canon(cfg.Apex)
	if cfg.Apex == "" || len(cfg.NSAddrs) == 0 {
		return nil, errors.New("refdns: a public view needs an apex and the addresses of its name server")
	}
	for _, z := range d.zones {
		if !hasSuffix(z.name, cfg.Apex) {
			return nil, errors.New("refdns: a zone is not below the apex")
		}
	}
	if cfg.Rate == 0 {
		cfg.Rate, cfg.Burst = defaultRate, defaultBurst
	}
	if len(cfg.Listen) == 0 {
		return nil, errors.New("refdns: a public view needs an address to listen on")
	}
	p := &Public{d: d, cfg: cfg, sem: make(chan struct{}, maxTCPConns), conns: map[netip.Prefix]int{},
		lim: &limiter{rate: cfg.Rate, burst: float64(cfg.Burst), buckets: map[netip.Prefix]*bucket{},
			global: bucket{tokens: globalBurst, last: time.Now()}}}
	for _, l := range cfg.Listen {
		if err := p.listen(l); err != nil {
			p.Close()
			return nil, err
		}
	}
	for _, c := range p.udp {
		p.wg.Add(1)
		go p.serveUDP(c)
	}
	for _, l := range p.tcp {
		p.wg.Add(1)
		go p.serveTCP(l)
	}
	return p, nil
}

// listen binds one address for UDP and, on the same port, for TCP. With port 0 the system picks
// the UDP port, which TCP may hold already; then it picks again, up to listenAttempts times.
func (p *Public) listen(address string) error {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return err
	}
	attempts := 1
	if addr.Port == 0 {
		attempts = listenAttempts
	}
	for {
		udp, err := net.ListenUDP("udp", addr)
		if err != nil {
			return err
		}
		tcp, err := net.Listen("tcp", udp.LocalAddr().String())
		if err == nil {
			p.udp, p.tcp = append(p.udp, udp), append(p.tcp, tcp)
			return nil
		}
		_ = udp.Close()
		if attempts--; attempts == 0 {
			return err
		}
	}
}

// Addr returns the first address the view listens on.
func (p *Public) Addr() string { return p.udp[0].LocalAddr().String() }

// Close stops the view.
func (p *Public) Close() {
	for _, c := range p.udp {
		_ = c.Close()
	}
	for _, l := range p.tcp {
		_ = l.Close()
	}
	p.wg.Wait()
}

func (p *Public) serveUDP(conn *net.UDPConn) {
	defer p.wg.Done()
	buf := make([]byte, maxQueryBytes)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if !p.lim.allow(from.Addr()) {
			continue
		}
		if out := p.answer(buf[:n], true); out != nil {
			_, _ = conn.WriteToUDPAddrPort(out, from)
		}
	}
}

func (p *Public) serveTCP(ln net.Listener) {
	defer p.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		from, err := netip.ParseAddrPort(c.RemoteAddr().String())
		if err != nil || !p.lim.allow(from.Addr()) || !p.takeConn(from.Addr()) {
			_ = c.Close()
			continue
		}
		select {
		case p.sem <- struct{}{}:
			p.wg.Add(1)
			go p.serveConn(c, from)
		default:
			p.releaseConn(from.Addr())
			_ = c.Close()
		}
	}
}

// takeConn counts a connection of a source, at most maxTCPPerSrc at a time.
func (p *Public) takeConn(a netip.Addr) bool {
	key, ok := sourceOf(a)
	if !ok {
		return false
	}
	p.connMu.Lock()
	defer p.connMu.Unlock()
	if p.conns[key] >= maxTCPPerSrc {
		return false
	}
	p.conns[key]++
	return true
}

func (p *Public) releaseConn(a netip.Addr) {
	key, _ := sourceOf(a)
	p.connMu.Lock()
	defer p.connMu.Unlock()
	if p.conns[key]--; p.conns[key] <= 0 {
		delete(p.conns, key)
	}
}

func (p *Public) serveConn(c net.Conn, from netip.AddrPort) {
	defer func() { _ = c.Close(); p.releaseConn(from.Addr()); <-p.sem; p.wg.Done() }()
	_ = c.SetDeadline(time.Now().Add(tcpDeadline))
	for range maxTCPQueries {
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint16(l[:])
		if n > maxQueryBytes || !p.lim.allow(from.Addr()) {
			return
		}
		query := make([]byte, n)
		if _, err := io.ReadFull(c, query); err != nil {
			return
		}
		out := p.answer(query, false)
		if out == nil {
			return
		}
		if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(out))), out...)); err != nil { //nolint:gosec // at most 64 KiB
			return
		}
	}
}

// answer packs the answer to a query, truncated over UDP beyond the size the query allows.
func (p *Public) answer(query []byte, udp bool) []byte {
	var q dnsmessage.Message
	if q.Unpack(query) != nil || q.Response || len(q.Questions) != 1 {
		return nil
	}
	resp := p.respond(q)
	limit := udpPlainBytes
	if size, ok := ednsSize(q); ok {
		limit = min(max(size, udpPlainBytes), udpEDNSBytes)
		var h dnsmessage.ResourceHeader
		_ = h.SetEDNS0(udpEDNSBytes, dnsmessage.RCodeSuccess, false)
		resp.Additionals = []dnsmessage.Resource{{Header: h, Body: &dnsmessage.OPTResource{}}}
	}
	out, err := resp.Pack()
	if err != nil {
		return nil
	}
	if udp && len(out) > limit {
		resp.Truncated, resp.Answers, resp.Authorities = true, nil, nil
		if out, err = resp.Pack(); err != nil {
			return nil
		}
	}
	return out
}

// ednsSize returns the UDP payload size the query advertises in its OPT record.
func ednsSize(q dnsmessage.Message) (int, bool) {
	i := slices.IndexFunc(q.Additionals, func(r dnsmessage.Resource) bool { return r.Header.Type == dnsmessage.TypeOPT })
	if i < 0 {
		return 0, false
	}
	return int(q.Additionals[i].Header.Class), true
}

// respond answers as the authoritative server of the apex.
func (p *Public) respond(q dnsmessage.Message) dnsmessage.Message {
	question := q.Questions[0]
	resp := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: q.ID, Response: true, OpCode: q.OpCode, RecursionDesired: q.RecursionDesired},
		Questions: q.Questions,
	}
	name := canon(question.Name.String())
	apex := p.cfg.Apex
	if q.OpCode != 0 || question.Class != dnsmessage.ClassINET || (name != apex && !hasSuffix(name, apex)) {
		resp.RCode = dnsmessage.RCodeRefused
		return resp
	}
	resp.Authoritative = true
	answers, found := p.records(name, question.Type)
	resp.Answers = answers
	switch {
	case len(answers) > 0:
	case found:
		resp.Authorities = []dnsmessage.Resource{p.soa()}
	default:
		resp.RCode = dnsmessage.RCodeNameError
		resp.Authorities = []dnsmessage.Resource{p.soa()}
	}
	return resp
}

// records returns the public records of the name and type, and whether the name exists.
func (p *Public) records(name string, typ dnsmessage.Type) ([]dnsmessage.Resource, bool) {
	apex, nsName := p.cfg.Apex, "ns1."+p.cfg.Apex
	switch name {
	case apex:
		switch typ {
		case dnsmessage.TypeSOA:
			return []dnsmessage.Resource{p.soa()}, true
		case TypeNS:
			return []dnsmessage.Resource{ns(apex, publicTTL, nsName)}, true
		}
		return nil, true
	case nsName:
		var out []dnsmessage.Resource
		for _, a := range p.cfg.NSAddrs {
			if (typ == TypeA && a.Is4()) || (typ == TypeAAAA && a.Is6()) {
				out = append(out, A(nsName, publicTTL, a))
			}
		}
		return out, true
	}
	z := p.d.zoneOf(name)
	if z == nil {
		return nil, false
	}
	inst := z.inst[0]
	if typ == TypeNS {
		return nil, inst.has(name)
	}
	var out []dnsmessage.Resource
	for _, rr := range inst.lookup(name, typ) {
		if public(rr) {
			out = append(out, rr)
		}
	}
	return out, inst.has(name)
}

// public reports whether a record may be shown publicly: no address that is not globally reachable.
func public(rr dnsmessage.Resource) bool {
	var a netip.Addr
	switch b := rr.Body.(type) {
	case *dnsmessage.AResource:
		a = netip.AddrFrom4(b.A)
	case *dnsmessage.AAAAResource:
		a = netip.AddrFrom16(b.AAAA)
	default:
		return true
	}
	return a.IsGlobalUnicast() && !a.IsPrivate()
}

func (p *Public) soa() dnsmessage.Resource {
	apex := p.cfg.Apex
	return dnsmessage.Resource{Header: header(apex, dnsmessage.TypeSOA, publicTTL), Body: &dnsmessage.SOAResource{
		NS: dnsmessage.MustNewName("ns1." + apex + "."), MBox: dnsmessage.MustNewName("hostmaster." + apex + "."),
		Serial: uint32(time.Now().Unix()), Refresh: publicTTL, Retry: soaRetry, Expire: soaExpire, MinTTL: soaMinimum, //nolint:gosec // until 2106
	}}
}

// has reports whether the name or a name below it has a record.
func (i *instance) has(name string) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.exists(name)
}

// limiter is a token bucket for each source, behind one for all sources together.
type limiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[netip.Prefix]*bucket
	global  bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// sourceOf is the key of a source: an IPv4 address or an IPv6 /64.
func sourceOf(a netip.Addr) (netip.Prefix, bool) {
	a = a.Unmap()
	bits := a.BitLen()
	if a.Is6() {
		bits = prefixBitsIPv6
	}
	key, err := a.Prefix(bits)
	return key, err == nil
}

// take refills the bucket and takes a token if there is one.
func (b *bucket) take(now time.Time, rate, burst float64) bool {
	b.tokens = min(burst, b.tokens+now.Sub(b.last).Seconds()*rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *limiter) allow(a netip.Addr) bool {
	key, ok := sourceOf(a)
	if !ok {
		return false
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxBuckets {
			l.evictIdle(now)
		}
		if len(l.buckets) >= maxBuckets {
			// Full of sources that are still limited: new sources wait, none is reset.
			return false
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	return b.take(now, l.rate, l.burst) && l.global.take(now, globalRate, globalBurst)
}

// evictIdle forgets the sources whose bucket would be full again: forgetting them changes nothing.
func (l *limiter) evictIdle(now time.Time) {
	refill := time.Duration(l.burst / l.rate * float64(time.Second))
	for k, b := range l.buckets {
		if now.Sub(b.last) >= refill {
			delete(l.buckets, k)
		}
	}
}
