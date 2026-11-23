// SPDX-License-Identifier: Apache-2.0

package ctlog

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/tlog"
)

// Fetcher gets a URL: the status and at most limit bytes of the body. CheckInclusion fetches
// only through it.
type Fetcher func(ctx context.Context, url string, limit int64) (status int, body []byte, err error)

// Inclusion is what a log's latest tree head says about an entry.
type Inclusion struct {
	// Included is set if the entry is in the tree.
	Included bool
	// TreeTime is the timestamp of the tree head.
	TreeTime time.Time
}

// ErrBadLog is returned when a proof or a tile does not lead to a tree head that verified: the
// log shows something other than what it signed.
var ErrBadLog = errors.New("ctlog: the proof of the log does not lead to its tree head")

// ErrBadTreeHead is returned when the tree head of a log does not verify with the key of the
// list, or cannot be read; it says nothing about the entry.
var ErrBadTreeHead = errors.New("ctlog: the tree head of the log does not verify with the key of the list")

// errNoAnswer wraps a failure to fetch, which says nothing about the log.
var errNoAnswer = errors.New("ctlog: the log did not answer")

// Limits of what is read from a log, and values of the formats.
const (
	maxTreeHeadBytes = 16 << 10
	maxProofBytes    = 64 << 10
	tileHeight       = 8
	tileBytes        = (1 << tileHeight) * tlog.HashSize
	leafIndexBytes   = 5
	sigTreeHash      = 1
	noteSignatureRFC = 0x05
	keyIDBytes       = 4
	timestampBytes   = 8
)

// CheckInclusion asks the log of the SCT, directly and without a service in between, whether
// its latest tree head includes the entry of the certificate, and verifies the tree head with
// the key of the log and the proof against it (RFC 6962 sections 3.4, 4.3 and 4.5; the
// static-ct-api of C2SP for tiled logs, with the leaf index of the SCT). A tree head that is
// not the log's, or a proof or tile that does not lead to it, is ErrBadLog; a log that does not
// answer is another error.
func CheckInclusion(ctx context.Context, fetch Fetcher, lg *Log, s SCT, leaf, issuer *x509.Certificate) (Inclusion, error) {
	tbs, err := PrecertTBS(leaf)
	if err != nil {
		return Inclusion{}, err
	}
	hash := LeafHash(s, tbs, issuer.RawSubjectPublicKeyInfo)
	if lg.URL != "" {
		return checkRFC6962(ctx, fetch, lg, hash)
	}
	return checkTiled(ctx, fetch, lg, s, hash)
}

// LeafHash is the hash of the MerkleTreeLeaf of the precertificate entry of the SCT.
func LeafHash(s SCT, tbs, issuerSPKI []byte) tlog.Hash {
	keyHash := sha256.Sum256(issuerSPKI)
	var b cryptobyte.Builder
	b.AddUint8(0) // version v1
	b.AddUint8(0) // leaf_type timestamped_entry
	b.AddUint64(s.Timestamp)
	b.AddUint16(entryPrecert)
	b.AddBytes(keyHash[:])
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(tbs) })
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(s.Extensions) })
	return tlog.RecordHash(b.BytesOrPanic())
}

// LeafIndex returns the index of the entry that a tiled log gives in the extension leaf_index
// of its SCT; the extensions must be exactly that one extension.
func LeafIndex(s SCT) (int64, bool) {
	in := cryptobyte.String(s.Extensions)
	var typ uint8
	var data cryptobyte.String
	if !in.ReadUint8(&typ) || typ != 0 || !in.ReadUint16LengthPrefixed(&data) || !in.Empty() || len(data) != leafIndexBytes {
		return 0, false
	}
	var idx int64
	for _, c := range data {
		idx = idx<<8 | int64(c)
	}
	return idx, true
}

// LeafIndexExtension returns the SCT extensions of a tiled log for the index.
func LeafIndexExtension(idx int64) []byte {
	b := []byte{0, 0, leafIndexBytes}
	for i := leafIndexBytes - 1; i >= 0; i-- {
		b = append(b, byte(idx>>(8*i))) //nolint:gosec // the low bytes of the index
	}
	return b
}

// treeHeadData is what a log signs for a tree head (RFC 6962 section 3.5).
func treeHeadData(ms uint64, size int64, root tlog.Hash) []byte {
	var b cryptobyte.Builder
	b.AddUint8(0)
	b.AddUint8(sigTreeHash)
	b.AddUint64(ms)
	b.AddUint64(uint64(size)) //nolint:gosec // a tree size is never negative
	b.AddBytes(root[:])
	return b.BytesOrPanic()
}

// SignTreeHead returns the digitally-signed struct of a tree head, as a log signs it.
func SignTreeHead(key crypto.Signer, size int64, root tlog.Hash, at time.Time) ([]byte, error) {
	digest := sha256.Sum256(treeHeadData(uint64(at.UnixMilli()), size, root)) //nolint:gosec // after 1970
	sig, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	alg := uint8(sigECDSA)
	if _, ok := key.Public().(*rsa.PublicKey); ok {
		alg = sigRSA
	}
	var b cryptobyte.Builder
	b.AddUint8(hashSHA256)
	b.AddUint8(alg)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(sig) })
	return b.Bytes()
}

// verifyTreeHead checks the digitally-signed struct of a tree head with the key of the log.
func verifyTreeHead(lg *Log, ms uint64, size int64, root tlog.Hash, signed []byte) bool {
	in := cryptobyte.String(signed)
	var hashAlg, sigAlg uint8
	var sig cryptobyte.String
	if !in.ReadUint8(&hashAlg) || !in.ReadUint8(&sigAlg) || !in.ReadUint16LengthPrefixed(&sig) || !in.Empty() || hashAlg != hashSHA256 {
		return false
	}
	digest := sha256.Sum256(treeHeadData(ms, size, root))
	switch k := lg.key.(type) {
	case *ecdsa.PublicKey:
		return sigAlg == sigECDSA && ecdsa.VerifyASN1(k, digest[:], sig)
	case *rsa.PublicKey:
		return sigAlg == sigRSA && rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) == nil
	}
	return false
}

func badLog(what string) error { return fmt.Errorf("%w: %s", ErrBadLog, what) }

func badHead(what string) error { return fmt.Errorf("%w: %s", ErrBadTreeHead, what) }

func get(ctx context.Context, fetch Fetcher, u string, limit int64) (int, []byte, error) {
	status, body, err := fetch(ctx, u, limit)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %w", errNoAnswer, err)
	}
	return status, body, nil
}

// RFC 6962 logs.

type sthJSON struct {
	TreeSize  int64  `json:"tree_size"`
	Timestamp uint64 `json:"timestamp"`
	Root      []byte `json:"sha256_root_hash"`
	Signature []byte `json:"tree_head_signature"`
}

func checkRFC6962(ctx context.Context, fetch Fetcher, lg *Log, hash tlog.Hash) (Inclusion, error) {
	base := strings.TrimSuffix(lg.URL, "/") + "/ct/v1/"
	status, body, err := get(ctx, fetch, base+"get-sth", maxTreeHeadBytes)
	if err != nil {
		return Inclusion{}, err
	}
	var sth sthJSON
	if status != http.StatusOK || json.Unmarshal(body, &sth) != nil || len(sth.Root) != tlog.HashSize || sth.TreeSize < 0 {
		return Inclusion{}, fmt.Errorf("%w: no tree head", errNoAnswer)
	}
	root := tlog.Hash(sth.Root)
	if !verifyTreeHead(lg, sth.Timestamp, sth.TreeSize, root, sth.Signature) {
		return Inclusion{}, badHead("the signature of the tree head")
	}
	head := Inclusion{TreeTime: time.UnixMilli(int64(sth.Timestamp))} //nolint:gosec // milliseconds since 1970
	if sth.TreeSize == 0 {
		return head, nil
	}
	q := url.Values{"hash": {base64.StdEncoding.EncodeToString(hash[:])}, "tree_size": {strconv.FormatInt(sth.TreeSize, 10)}}
	status, body, err = get(ctx, fetch, base+"get-proof-by-hash?"+q.Encode(), maxProofBytes)
	switch {
	case err != nil:
		return Inclusion{}, err
	case status == http.StatusNotFound:
		return head, nil
	case status != http.StatusOK:
		return Inclusion{}, fmt.Errorf("%w: status %d", errNoAnswer, status)
	}
	var p struct {
		LeafIndex int64    `json:"leaf_index"`
		AuditPath [][]byte `json:"audit_path"`
	}
	if json.Unmarshal(body, &p) != nil {
		return Inclusion{}, badLog("the proof cannot be read")
	}
	proof := make(tlog.RecordProof, len(p.AuditPath))
	for i, h := range p.AuditPath {
		if len(h) != tlog.HashSize {
			return Inclusion{}, badLog("a hash of the proof")
		}
		proof[i] = tlog.Hash(h)
	}
	if p.LeafIndex < 0 || p.LeafIndex >= sth.TreeSize || tlog.CheckRecord(proof, sth.TreeSize, root, p.LeafIndex, hash) != nil {
		return Inclusion{}, badLog("the proof does not lead to the tree head")
	}
	head.Included = true
	return head, nil
}

// Tiled logs (static-ct-api).

// Origin is the origin line of the checkpoints of a tiled log: its submission prefix without
// the scheme and the trailing slash.
func Origin(submission string) string {
	return strings.TrimSuffix(strings.TrimPrefix(submission, "https://"), "/")
}

// CheckpointKeyID is the key ID of the signature of a tiled log on its checkpoints.
func CheckpointKeyID(origin string, logID []byte) []byte {
	sum := sha256.Sum256(append(append([]byte(origin+"\n"), noteSignatureRFC), logID...))
	return sum[:keyIDBytes]
}

// FormatCheckpoint returns a checkpoint signed by the key of a tiled log.
func FormatCheckpoint(key crypto.Signer, origin string, size int64, root tlog.Hash, at time.Time) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	logID := sha256.Sum256(der)
	signed, err := SignTreeHead(key, size, root, at)
	if err != nil {
		return nil, err
	}
	sig := binary.BigEndian.AppendUint64(append([]byte{}, CheckpointKeyID(origin, logID[:])...), uint64(at.UnixMilli())) //nolint:gosec // after 1970
	sig = append(sig, signed...)
	body := fmt.Sprintf("%s\n%d\n%s\n", origin, size, base64.StdEncoding.EncodeToString(root[:]))
	return []byte(body + "\n— " + origin + " " + base64.StdEncoding.EncodeToString(sig) + "\n"), nil
}

// parseCheckpoint verifies a checkpoint with the key of the log and returns its tree.
func parseCheckpoint(lg *Log, text []byte) (tlog.Tree, time.Time, error) {
	origin := Origin(lg.SubmissionURL)
	body, sigs, ok := bytes.Cut(text, []byte("\n\n"))
	lines := strings.Split(string(body), "\n")
	if !ok || len(lines) != 3 || lines[0] != origin {
		return tlog.Tree{}, time.Time{}, badHead("the checkpoint is not one of this log")
	}
	size, err1 := strconv.ParseInt(lines[1], 10, 64)
	root, err2 := base64.StdEncoding.DecodeString(lines[2])
	if err1 != nil || err2 != nil || size < 0 || len(root) != tlog.HashSize {
		return tlog.Tree{}, time.Time{}, badHead("the checkpoint cannot be read")
	}
	keyID := CheckpointKeyID(origin, lg.LogID)
	for _, line := range strings.Split(string(sigs), "\n") {
		name, b64, ok := strings.Cut(strings.TrimPrefix(line, "— "), " ")
		sig, err := base64.StdEncoding.DecodeString(b64)
		if !ok || name != origin || err != nil || len(sig) < keyIDBytes+timestampBytes || !bytes.Equal(sig[:keyIDBytes], keyID) {
			continue
		}
		ms := binary.BigEndian.Uint64(sig[keyIDBytes:])
		if !verifyTreeHead(lg, ms, size, tlog.Hash(root), sig[keyIDBytes+timestampBytes:]) {
			return tlog.Tree{}, time.Time{}, badHead("the signature of the checkpoint")
		}
		return tlog.Tree{N: size, Hash: tlog.Hash(root)}, time.UnixMilli(int64(ms)), nil //nolint:gosec // milliseconds since 1970
	}
	return tlog.Tree{}, time.Time{}, badHead("the checkpoint has no signature of the log")
}

// tiles reads the hash tiles of a tiled log.
type tiles struct {
	ctx    context.Context
	fetch  Fetcher
	prefix string
	failed error
}

func (t *tiles) Height() int { return tileHeight }

func (t *tiles) ReadTiles(list []tlog.Tile) ([][]byte, error) {
	out := make([][]byte, len(list))
	for i, tile := range list {
		status, body, err := t.read(tile)
		if err == nil && status != http.StatusOK {
			err = fmt.Errorf("%w: status %d", errNoAnswer, status)
		}
		if err != nil {
			t.failed = err
			return nil, err
		}
		out[i] = body
	}
	return out, nil
}

// read fetches a tile; a partial tile that is gone because the log grew is taken from the
// full tile, as the static-ct-api allows.
func (t *tiles) read(tile tlog.Tile) (int, []byte, error) {
	status, body, err := get(t.ctx, t.fetch, t.prefix+tilePath(tile), tileBytes)
	if err != nil || status != http.StatusNotFound || tile.W == 1<<tileHeight {
		return status, body, err
	}
	full := tile
	full.W = 1 << tileHeight
	status, body, err = get(t.ctx, t.fetch, t.prefix+tilePath(full), tileBytes)
	if err == nil && status == http.StatusOK && len(body) == tileBytes {
		body = body[:tile.W*tlog.HashSize]
	}
	return status, body, err
}

// tilePath is the path of a tile in the static-ct-api, which has no height in it.
func tilePath(tile tlog.Tile) string {
	return "tile/" + strings.TrimPrefix(tile.Path(), "tile/"+strconv.Itoa(tileHeight)+"/")
}

func (t *tiles) SaveTiles([]tlog.Tile, [][]byte) {}

func checkTiled(ctx context.Context, fetch Fetcher, lg *Log, s SCT, hash tlog.Hash) (Inclusion, error) {
	idx, ok := LeafIndex(s)
	if !ok {
		return Inclusion{}, badLog("the SCT of a tiled log has no leaf index")
	}
	prefix := strings.TrimSuffix(lg.MonitoringURL, "/") + "/"
	status, body, err := get(ctx, fetch, prefix+"checkpoint", maxTreeHeadBytes)
	if err != nil {
		return Inclusion{}, err
	}
	if status != http.StatusOK {
		return Inclusion{}, fmt.Errorf("%w: status %d", errNoAnswer, status)
	}
	tree, at, err := parseCheckpoint(lg, body)
	if err != nil {
		return Inclusion{}, err
	}
	head := Inclusion{TreeTime: at}
	if idx >= tree.N {
		return head, nil
	}
	tr := &tiles{ctx: ctx, fetch: fetch, prefix: prefix}
	proof, err := tlog.ProveRecord(tree.N, idx, tlog.TileHashReader(tree, tr))
	if tr.failed != nil {
		return Inclusion{}, tr.failed
	}
	if err != nil || tlog.CheckRecord(proof, tree.N, tree.Hash, idx, hash) != nil {
		return Inclusion{}, badLog("the tiles do not lead to the checkpoint, or the entry is another one")
	}
	head.Included = true
	return head, nil
}
