// SPDX-License-Identifier: Apache-2.0

package liveconf

import (
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"slices"
	"time"

	"golang.org/x/crypto/acme"
)

// maxCacheWait is the longest TTL of the challenge records, in seconds, that the tool waits
// out before it orders the refusals (RELAY-v0 section 8.3).
const maxCacheWait = 600

// problemSeveralAuthz is the word of the tool for an order of one name with more than one
// authorization to complete.
const problemSeveralAuthz = "several-authorizations"

// wanted is an order the tool places: the account and the identifier.
type wanted struct {
	c  *acme.Client
	id string
}

// ordering is an order on its way: the challenge whose value the operator publishes, or how the
// order ended before that.
type ordering struct {
	wanted
	order *acme.Order
	// authz is the URL of the authorization to complete, empty if the CA asks for none.
	authz string
	chal  *acme.Challenge
	value string
	end   *outcome
}

// orders places the orders and completes them together: the operator publishes the values of
// all of them at once (at most two, RELAY-v0 section 5.6), and the CA validates them only when
// it can no longer hold the values published before. Only a failure of the operator is an error.
func (is *issuing) orders(ctx context.Context, all []wanted) ([]outcome, error) {
	started := make([]*ordering, len(all))
	var values []string
	for i, w := range all {
		started[i] = is.start(ctx, w)
		if started[i].end == nil && started[i].authz != "" {
			values = append(values, started[i].value)
		}
	}
	if len(values) > 0 {
		end, err := is.publish(ctx, values)
		if err != nil {
			return nil, err
		}
		for _, o := range started {
			if o.end == nil && o.authz != "" {
				o.end = end
			}
		}
	}
	out := make([]outcome, len(started))
	for i, o := range started {
		out[i] = is.finish(ctx, o)
	}
	return out, nil
}

// start places an order and finds the DNS-01 challenge of its one authorization to complete.
func (is *issuing) start(ctx context.Context, w wanted) *ordering {
	o := &ordering{wanted: w}
	ctx, cancel := context.WithTimeout(ctx, is.s.r.env.Timing.Slow)
	defer cancel()
	ord, err := w.c.AuthorizeOrder(ctx, acme.DomainIDs(w.id))
	if err != nil {
		return o.ended(failed(err))
	}
	o.order = ord
	for _, u := range ord.AuthzURLs {
		z, err := w.c.GetAuthorization(ctx, u)
		switch {
		case err != nil:
			return o.ended(failed(err))
		case z.Status == acme.StatusValid:
			continue
		case o.authz != "":
			return o.ended(outcome{problem: problemSeveralAuthz})
		}
		i := slices.IndexFunc(z.Challenges, func(ch *acme.Challenge) bool { return ch.Type == "dns-01" })
		if i < 0 {
			return o.ended(outcome{problem: problemNoDNS01})
		}
		o.authz, o.chal = u, z.Challenges[i]
		o.value = must(w.c.DNS01ChallengeRecord(o.chal.Token))
	}
	return o
}

func (o *ordering) ended(end outcome) *ordering {
	o.end = &end
	return o
}

// publish has the operator publish the values, waits until they show on the name servers of
// the name domain (the gateway checks this itself before it asks the CA, RELAY-v0 section 5.6),
// and then for the TTL of the values published before, which a resolver of the CA may still
// hold. A non-nil outcome ends the orders of the values.
func (is *issuing) publish(ctx context.Context, values []string) (*outcome, error) {
	earlier := is.kept
	if end, err := is.publishValues(ctx, values); end != nil || err != nil {
		return end, err
	}
	if err := sleep(ctx, ttlWait(is.s.r.env.Timing, earlier)); err != nil {
		return &outcome{stopped: true}, nil
	}
	return nil, nil
}

// ttlWait is how long the tool waits for a record with the TTL to leave every cache: nothing
// for no record, else the TTL and a second, in seconds of TTLUnit (a second if unset).
func ttlWait(t Timing, ttl uint32) time.Duration {
	if ttl == 0 {
		return 0
	}
	return time.Duration(ttl+1) * cmp.Or(t.TTLUnit, time.Second)
}

// publishValues publishes the values and waits until they show; it remembers their TTL.
func (is *issuing) publishValues(ctx context.Context, values []string) (*outcome, error) {
	ctx, cancel := context.WithTimeout(ctx, is.s.r.env.Timing.Slow)
	defer cancel()
	_, err := is.s.c.Challenge(ctx, is.b.id, is.b.paired.Installation.ACMEChallenge, values)
	name, fatal := apiName(err)
	switch {
	case fatal != nil:
		return nil, fatal
	case undecided(name):
		return &outcome{problem: "operator-" + name}, nil
	case err != nil:
		return &outcome{problem: problemChallengeRefused}, nil
	}
	ttl, err := is.s.dns.waitTexts(ctx, "_acme-challenge."+is.name, values)
	if err != nil {
		// The end of the tool's own time limit is no failure of the operator.
		if ctx.Err() != nil {
			return &outcome{stopped: true}, nil
		}
		return &outcome{problem: problemNotVisible}, nil
	}
	is.kept = max(is.kept, ttl)
	return nil, nil
}

// finish asks the CA to validate the challenge of the order and to issue the certificate.
func (is *issuing) finish(ctx context.Context, o *ordering) outcome {
	if o.end != nil {
		return *o.end
	}
	ctx, cancel := context.WithTimeout(ctx, is.s.r.env.Timing.Slow)
	defer cancel()
	if o.authz != "" {
		if _, err := o.c.Accept(ctx, o.chal); err != nil {
			return failed(err)
		}
		if _, err := o.c.WaitAuthorization(ctx, o.authz); err != nil {
			return failed(err)
		}
	}
	key := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	csr := must(x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{o.id}}, key))
	chain, _, err := o.c.CreateOrderCert(ctx, o.order.FinalizeURL, csr, true)
	if err != nil {
		return failed(err)
	}
	return outcome{chain: chain, key: &key.PublicKey}
}
