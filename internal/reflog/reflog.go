// SPDX-License-Identifier: Apache-2.0

// Package reflog is a reference Certificate Transparency log for the tests of relay-conformance
// and for the reference CA, and for them only: an RFC 6962 log (get-sth, get-proof-by-hash) or a
// tiled log of the static-ct-api (checkpoint, hash tiles), kept in memory, with switches that
// make it misbehave. Neither the tool nor the files of package relay import it (a test checks that).
package reflog

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/home-mandate/relay-spec/internal/ctlog"
)

const (
	tileHeight   = 8
	listInterval = 365 * 24 * time.Hour
)

// Log is a reference log.
type Log struct {
	prefix string
	path   string
	tiled  bool
	key    *ecdsa.PrivateKey

	mu        sync.Mutex
	include   bool
	badHead   bool
	badProof  bool
	noPartial bool
	mmd       int
	hashes    []tlog.Hash
	n         int64
	positions map[tlog.Hash]int64
}

// New returns an empty log whose URLs begin with prefix (https, ending in "/").
func New(prefix string, tiled bool) *Log {
	u, err := url.Parse(prefix)
	if err != nil || u.Scheme != "https" || !strings.HasSuffix(u.Path, "/") {
		panic("reflog: the prefix is no https URL ending in /")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("reflog: " + err.Error())
	}
	return &Log{prefix: prefix, path: u.Path, tiled: tiled, key: key, include: true, positions: map[tlog.Hash]int64{}}
}

// Prefix returns the prefix of the log's URLs.
func (l *Log) Prefix() string { return l.prefix }

// SetInclude makes the log include, or leave out, the entries it gives SCTs for from now on.
func (l *Log) SetInclude(on bool) { l.set(func() { l.include = on }) }

// SetBadTreeHead makes the signature of the log's tree heads invalid.
func (l *Log) SetBadTreeHead(on bool) { l.set(func() { l.badHead = on }) }

// SetBadProof makes the proofs or hash tiles of the log wrong.
func (l *Log) SetBadProof(on bool) { l.set(func() { l.badProof = on }) }

// SetDropPartialTiles makes the log answer 404 for partial tiles and serve the full tile, padded,
// as a log that has grown since.
func (l *Log) SetDropPartialTiles(on bool) { l.set(func() { l.noPartial = on }) }

// SetMMD sets the maximum merge delay the log list gives for the log, in seconds.
func (l *Log) SetMMD(seconds int) { l.set(func() { l.mmd = seconds }) }

// Reset empties the log.
func (l *Log) Reset() {
	l.set(func() { l.hashes, l.n, l.positions = nil, 0, map[tlog.Hash]int64{} })
}

func (l *Log) set(f func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f()
}

// ReadHashes serves the stored hashes of the tree to package tlog; the lock is held.
func (l *Log) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, idx := range indexes {
		if idx < 0 || idx >= int64(len(l.hashes)) {
			return nil, errors.New("reflog: no such hash")
		}
		out[i] = l.hashes[idx]
	}
	return out, nil
}

// Submit gives the SCT for a precertificate with the TBSCertificate tbs (without poison and
// SCTs) and appends its entry, unless the log leaves entries out.
func (l *Log) Submit(tbs, issuerSPKI []byte, at time.Time) (ctlog.SCT, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var ext []byte
	if l.tiled {
		ext = ctlog.LeafIndexExtension(l.n)
	}
	s, err := ctlog.SignPrecertWithExtensions(l.key, tbs, issuerSPKI, at, ext)
	if err != nil || !l.include {
		return s, err
	}
	h := ctlog.LeafHash(s, tbs, issuerSPKI)
	stored, err := tlog.StoredHashesForRecordHash(l.n, h, l)
	if err != nil {
		return s, err
	}
	l.hashes = append(l.hashes, stored...)
	l.positions[h] = l.n
	l.n++
	return s, nil
}

// entry is the log's entry in a log list.
func (l *Log) entry() (map[string]any, error) {
	der, err := x509.MarshalPKIXPublicKey(&l.key.PublicKey)
	if err != nil {
		return nil, err
	}
	id := sha256.Sum256(der)
	now := time.Now().UTC()
	l.mu.Lock()
	mmd := l.mmd
	l.mu.Unlock()
	e := map[string]any{
		"description": "Reference log " + l.prefix, "log_id": id[:], "key": der, "mmd": mmd,
		"state":             map[string]any{"usable": map[string]any{"timestamp": now.Add(-time.Hour)}},
		"temporal_interval": map[string]any{"start_inclusive": now.Add(-listInterval), "end_exclusive": now.Add(listInterval)},
	}
	if l.tiled {
		e["submission_url"], e["monitoring_url"] = l.prefix, l.prefix
	} else {
		e["url"] = l.prefix
	}
	return e, nil
}

// List returns a log list with the logs, each of its own operator.
func List(logs ...*Log) (*ctlog.List, error) {
	ops := []map[string]any{}
	for i, l := range logs {
		e, err := l.entry()
		if err != nil {
			return nil, err
		}
		op := map[string]any{"name": "Reference log operator " + strconv.Itoa(i+1)}
		if l.tiled {
			op["tiled_logs"] = []map[string]any{e}
		} else {
			op["logs"] = []map[string]any{e}
		}
		ops = append(ops, op)
	}
	data, err := json.Marshal(map[string]any{"version": "1", "log_list_timestamp": time.Now().UTC(), "operators": ops})
	if err != nil {
		return nil, err
	}
	return ctlog.ParseList(data)
}

// Handler serves the log at the path of its prefix.
func (l *Log) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest, ok := strings.CutPrefix(r.URL.Path, l.path)
		switch {
		case !ok || r.Method != http.MethodGet:
			http.NotFound(w, r)
		case !l.tiled && rest == "ct/v1/get-sth":
			l.sth(w)
		case !l.tiled && rest == "ct/v1/get-proof-by-hash":
			l.proof(w, r)
		case l.tiled && rest == "checkpoint":
			l.checkpoint(w)
		case l.tiled && strings.HasPrefix(rest, "tile/"):
			l.tile(w, r, rest)
		default:
			http.NotFound(w, r)
		}
	})
}

// head returns the size and root of the current tree; the lock is held.
func (l *Log) head() (int64, tlog.Hash, error) {
	root, err := tlog.TreeHash(l.n, l)
	return l.n, root, err
}

func (l *Log) sth(w http.ResponseWriter) {
	l.mu.Lock()
	defer l.mu.Unlock()
	at := time.Now()
	size, root, err := l.head()
	var signed []byte
	if err == nil {
		signed, err = ctlog.SignTreeHead(l.key, size, root, at)
	}
	if err != nil {
		http.Error(w, "no tree head", http.StatusInternalServerError)
		return
	}
	if l.badHead {
		signed[len(signed)-1] ^= 1
	}
	writeJSON(w, map[string]any{"tree_size": size, "timestamp": at.UnixMilli(), "sha256_root_hash": root[:], "tree_head_signature": signed})
}

func (l *Log) proof(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	raw, err1 := base64.StdEncoding.DecodeString(r.URL.Query().Get("hash"))
	size, err2 := strconv.ParseInt(r.URL.Query().Get("tree_size"), 10, 64)
	if err1 != nil || err2 != nil || len(raw) != tlog.HashSize {
		http.Error(w, "no such entry", http.StatusNotFound)
		return
	}
	idx, found := l.positions[tlog.Hash(raw)]
	if size > l.n || !found || idx >= size {
		http.Error(w, "no such entry", http.StatusNotFound)
		return
	}
	p, err := tlog.ProveRecord(size, idx, l)
	if err != nil {
		http.Error(w, "no proof", http.StatusInternalServerError)
		return
	}
	path := make([][]byte, len(p))
	for i, h := range p {
		path[i] = append([]byte{}, h[:]...)
	}
	if l.badProof && len(path) > 0 {
		path[0][0] ^= 1
	}
	writeJSON(w, map[string]any{"leaf_index": idx, "audit_path": path})
}

// checkpoint serves the signed checkpoint; with a bad tree head, the signature is one over
// another root, under the right key ID.
func (l *Log) checkpoint(w http.ResponseWriter) {
	l.mu.Lock()
	defer l.mu.Unlock()
	at := time.Now()
	size, root, err := l.head()
	signedRoot := root
	if l.badHead {
		signedRoot[0] ^= 1
	}
	var text []byte
	if err == nil {
		text, err = ctlog.FormatCheckpoint(l.key, ctlog.Origin(l.prefix), size, signedRoot, at)
	}
	if err != nil {
		http.Error(w, "no checkpoint", http.StatusInternalServerError)
		return
	}
	if l.badHead {
		_, sig, _ := strings.Cut(string(text), "\n\n")
		body := ctlog.Origin(l.prefix) + "\n" + strconv.FormatInt(size, 10) + "\n" + base64.StdEncoding.EncodeToString(root[:]) + "\n"
		text = []byte(body + "\n" + sig)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(text)
}

func (l *Log) tile(w http.ResponseWriter, r *http.Request, rest string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	t, err := tlog.ParseTilePath("tile/" + strconv.Itoa(tileHeight) + "/" + strings.TrimPrefix(rest, "tile/"))
	full := 1 << tileHeight
	if err != nil || t.L < 0 || (l.noPartial && t.W < full) {
		http.NotFound(w, r)
		return
	}
	padding := 0
	if l.noPartial {
		// The hashes this tree has; a grown log would have the rest of the full tile.
		have := int(min(l.n>>(tileHeight*t.L)-t.N*int64(full), int64(full))) //nolint:gosec // at most 256
		padding, t.W = (full-have)*tlog.HashSize, have
	}
	data, err := tlog.ReadTileData(t, l)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	data = append(data, make([]byte, padding)...)
	if l.badProof {
		data[0] ^= 1
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(data)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
