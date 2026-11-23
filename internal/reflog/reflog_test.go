// SPDX-License-Identifier: Apache-2.0

package reflog_test

import (
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/home-mandate/relay-spec/internal/reflog"
)

func get(l *reflog.Log, method, url string) (int, string) {
	rec := httptest.NewRecorder()
	l.Handler().ServeHTTP(rec, httptest.NewRequest(method, url, nil))
	return rec.Code, rec.Body.String()
}

// TestTheLogServesItsEndpoints: the paths of each kind of log, and nothing else.
func TestTheLogServesItsEndpoints(t *testing.T) {
	a := reflog.New("https://ct.example.com/a/", false)
	b := reflog.New("https://ct.example.com/b/", true)
	for _, l := range []*reflog.Log{a, b} {
		for range 3 {
			if _, err := l.Submit([]byte{0x30, 0}, []byte{1}, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, tt := range map[string]struct {
		l      *reflog.Log
		method string
		url    string
		want   int
	}{
		"sth":                  {a, "GET", "https://ct.example.com/a/ct/v1/get-sth", 200},
		"sth of a tiled log":   {b, "GET", "https://ct.example.com/b/ct/v1/get-sth", 404},
		"checkpoint":           {b, "GET", "https://ct.example.com/b/checkpoint", 200},
		"checkpoint of 6962":   {a, "GET", "https://ct.example.com/a/checkpoint", 404},
		"partial tile":         {b, "GET", "https://ct.example.com/b/tile/0/000.p/3", 200},
		"data tile":            {b, "GET", "https://ct.example.com/b/tile/data/000.p/3", 404},
		"bad tile path":        {b, "GET", "https://ct.example.com/b/tile/0/x", 404},
		"tile beyond the tree": {b, "GET", "https://ct.example.com/b/tile/0/001", 404},
		"proof without hash":   {a, "GET", "https://ct.example.com/a/ct/v1/get-proof-by-hash?tree_size=3", 404},
		"post":                 {a, "POST", "https://ct.example.com/a/ct/v1/get-sth", 404},
		"another prefix":       {a, "GET", "https://ct.example.com/z/ct/v1/get-sth", 404},
		"unknown path":         {a, "GET", "https://ct.example.com/a/other", 404},
	} {
		if code, _ := get(tt.l, tt.method, tt.url); code != tt.want {
			t.Errorf("%s: %d, want %d", name, code, tt.want)
		}
	}
	q := "hash=" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "&tree_size=9"
	if code, _ := get(a, "GET", "https://ct.example.com/a/ct/v1/get-proof-by-hash?"+q); code != 404 {
		t.Errorf("a tree size beyond the tree: %d", code)
	}
	a.Reset()
	if _, body := get(a, "GET", "https://ct.example.com/a/ct/v1/get-sth"); !strings.Contains(body, `"tree_size":0`) {
		t.Errorf("after a reset: %s", body)
	}
	b.SetMMD(60)
	list, err := reflog.List(a, b)
	if err != nil || len(list.Operators) != 2 || list.Operators[1].TiledLogs[0].MMD != 60 {
		t.Errorf("list %+v, %v", list, err)
	}
}

func TestAPrefixMustBeHTTPSWithASlash(t *testing.T) {
	for _, prefix := range []string{"http://ct.example.com/a/", "https://ct.example.com/a", "::"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%q: no panic", prefix)
				}
			}()
			reflog.New(prefix, false)
		}()
	}
}

// TestTheSwitchesChangeWhatTheLogServes: with each switch the log still answers, with wrong
// content; ctlog's tests check that the content is wrong.
func TestTheSwitchesChangeWhatTheLogServes(t *testing.T) {
	for _, tiled := range []bool{false, true} {
		l := reflog.New("https://ct.example.com/s/", tiled)
		s, err := l.Submit([]byte{0x30, 0}, []byte{1}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = l.Submit([]byte{0x30, 1}, []byte{1}, time.Now())
		_ = s
		urls := []string{"https://ct.example.com/s/ct/v1/get-sth"}
		if tiled {
			urls = []string{"https://ct.example.com/s/checkpoint", "https://ct.example.com/s/tile/0/000.p/2"}
		}
		for _, on := range []func(bool){l.SetBadTreeHead, l.SetBadProof} {
			on(true)
			for _, u := range urls {
				if code, body := get(l, "GET", u); code != 200 || body == "" {
					t.Errorf("tiled %v, %s: %d", tiled, u, code)
				}
			}
			on(false)
		}
		l.SetInclude(false)
		if _, err := l.Submit([]byte{0x30, 2}, []byte{1}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	l := reflog.New("https://ct.example.com/p/", true)
	_, _ = l.Submit([]byte{0x30, 0}, []byte{1}, time.Now())
	l.SetDropPartialTiles(true)
	if code, _ := get(l, "GET", "https://ct.example.com/p/tile/0/000.p/1"); code != 404 {
		t.Errorf("a partial tile: %d", code)
	}
	if code, body := get(l, "GET", "https://ct.example.com/p/tile/0/000"); code != 200 || len(body) != 8192 {
		t.Errorf("the full tile: %d, %d bytes", code, len(body))
	}
}
