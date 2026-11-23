// SPDX-License-Identifier: Apache-2.0

package refdns

import (
	"net/netip"
	"testing"
	"time"
)

// TestTheLimiterForgetsOnlyIdleSources: a full table drops the sources whose bucket is full
// again; while every source is still limited, new sources are refused and none is reset.
func TestTheLimiterForgetsOnlyIdleSources(t *testing.T) {
	l := &limiter{rate: 1, burst: 2, buckets: map[netip.Prefix]*bucket{}, global: bucket{tokens: globalBurst, last: time.Now()}}
	busy := netip.MustParseAddr("192.0.2.1")
	for range 2 {
		if !l.allow(busy) {
			t.Fatal("the burst was refused")
		}
	}
	for i := range maxBuckets - 1 {
		l.buckets[netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), 32)] = &bucket{tokens: 0, last: time.Now()}
	}
	if l.allow(netip.MustParseAddr("198.51.100.1")) {
		t.Error("a new source was let in while the table is full of limited sources")
	}
	if l.allow(busy) {
		t.Error("the busy source got a new burst")
	}
	for k := range l.buckets {
		l.buckets[k].last = time.Now().Add(-time.Hour)
	}
	if !l.allow(netip.MustParseAddr("198.51.100.1")) || len(l.buckets) != 1 {
		t.Errorf("idle sources were not forgotten: %d left", len(l.buckets))
	}
	if !l.allow(netip.MustParseAddr("::ffff:198.51.100.1")) || len(l.buckets) != 1 {
		t.Error("an IPv4-mapped address is another source")
	}
	l.global.tokens = 0
	if l.allow(netip.MustParseAddr("198.51.100.2")) {
		t.Error("the global limit was passed")
	}
	if l.allow(netip.Addr{}) {
		t.Error("an invalid address was let in")
	}
}
