// SPDX-License-Identifier: Apache-2.0

package refgateway

import (
	"errors"
	"slices"
)

// PinFault is a deliberate defect of the decision on new pins.
type PinFault uint64

// Defects of the decision on a pins message. The first group accepts what must be ignored,
// the second ignores or closes what must not be.
const (
	PinBackupChange       PinFault = 1 << iota // an active connection may change the backup pins
	PinNullActive                              // the active pins may be empty
	PinNullBackup                              // a backup connection may leave the backup pins empty
	PinOverlap                                 // a pin may be in both kinds
	PinNine                                    // nine pins are allowed
	PinPerKind                                 // at most eight per kind instead of in all
	PinKindFromCurrent                         // the kind is the one the pin has in the stored set now
	PinNoPinCheck                              // the pin of the connection need not be stored
	PinApplyIgnored                            // a set that is answered ignored is stored all the same
	PinNoClose                                 // the connection is never closed
	PinAlwaysBackup                            // every connection has the rights of a backup pin
	PinOrderCompare                            // sets are equal only in the same order
	PinEqualIgnored                            // the same set is answered ignored
	PinEqualLast                               // equality is checked after the rules
	PinSwapEqual                               // the kinds exchanged count as the same set
	PinRequireConnPin                          // the new set must hold the pin of the connection
	PinCloseOnKindChange                       // the connection is closed when its pin is stored in another kind than at the handshake
	PinBackupKeepsBackup                       // a backup connection must keep the backup pins
	PinBackupKeepsActive                       // a backup connection must keep the active pins
	PinSeven                                   // at most seven pins
	PinActiveOnlyOne                           // an active connection may announce one active pin only
	PinOtherNoClose                            // a set stored through another connection closes only the connection it arrived on
	PinCloseOldSet                             // the connection is closed when its pin is not in the set stored before
	PinOtherAlwaysClose                        // a set stored through another connection closes this connection whatever it holds
	PinNoLimit                                 // a connection with an active pin may store new sets at any rate
	PinLimitBackup                             // the limit also holds for a connection with a backup pin
	PinLimitExclusive                          // a set exactly an hour after the last one is still over the limit
	PinLimitEqual                              // the limit also refuses the set that is already stored
	PinLimitIgnoredCounts                      // an ignored set starts the hour again
	PinLimitPerConnection                      // the hour runs for each connection, not for the gateway
	PinLimitRemoval                            // the limit also holds for a set that only removes pins
)

// limitMinutes: over a connection with an active pin, a gateway stores at most one new set of
// pins an hour (RELAY-v0 section 4.7).
const limitMinutes = 60

// minutesPerDay stands for a time that a case does not state: an hour or more.
const minutesPerDay = 24 * 60

// Pins is a set of pins: SHA-256 digests in base64url.
type Pins struct {
	Active []string `json:"active"`
	Backup []string `json:"backup"`
}

// Kind of a pin.
type Kind int

// Kinds of pins.
const (
	KindActive Kind = iota
	KindBackup
)

const maxPins = 8

func (p Pins) kindOf(pin string) (Kind, bool) {
	if slices.Contains(p.Active, pin) {
		return KindActive, true
	}
	return KindBackup, slices.Contains(p.Backup, pin)
}

// PinStep is one pins message of a case, and what the case says happens.
type PinStep struct {
	Pins
	Expected    string `json:"expected"`
	StoredAfter Pins   `json:"stored_after"`
	Connection  string `json:"connection"`
	// ArrivedOn is "other" for a set that another control connection stored, "" for this one.
	ArrivedOn string `json:"arrived_on"`
	// Kind is, for a set stored through another connection, the kind of that connection's pin:
	// "active" or "backup"; empty when the case does not say.
	Kind string `json:"kind"`
	// AfterMinutes is the time since the step before, or for the first step since the start
	// of the case; nil stands for an hour or more, and for the first step for none.
	AfterMinutes *int `json:"after_minutes"`
}

// PinsInput is the input of a pins case.
type PinsInput struct {
	Stored        Pins   `json:"stored"`
	ConnectionPin string `json:"connection_pin"`
	// StoredMinutesAgo is how long before the start of the case the stored set was stored over
	// a connection with an active pin; nil stands for an hour or more.
	StoredMinutesAgo *int      `json:"stored_minutes_ago"`
	Steps            []PinStep `json:"steps"`
}

// PinOutcome is what the gateway does with one message.
type PinOutcome struct {
	Answer string
	Stored Pins
	Closed bool
}

// ErrPinCase is returned for a case whose pin of the connection is not stored.
var ErrPinCase = errors.New("refgateway: the pin of the connection is not stored")

// RunPins plays the steps of a case on one connection.
func RunPins(in PinsInput, f PinFault) ([]PinOutcome, error) {
	kind, ok := in.Stored.kindOf(in.ConnectionPin)
	if !ok {
		return nil, ErrPinCase
	}
	if f.Has(PinAlwaysBackup) {
		kind = KindBackup
	}
	stored := in.Stored
	since := minutesOr(in.StoredMinutesAgo)
	out := make([]PinOutcome, 0, len(in.Steps))
	for i, step := range in.Steps {
		if i > 0 || step.AfterMinutes != nil {
			since += minutesOr(step.AfterMinutes)
		}
		var o PinOutcome
		if step.ArrivedOn == "other" {
			o = storedElsewhere(stored, in.ConnectionPin, kind, step.Pins, f)
			if step.Kind == "active" && !sameSets(stored, step.Pins, 0) && !f.Has(PinLimitPerConnection) {
				since = 0
			}
		} else {
			o = Announce(stored, in.ConnectionPin, kind, step.Pins, f)
			if overLimit(stored, step.Pins, kind, since, o, f) {
				o = PinOutcome{Answer: "ignored", Stored: stored, Closed: closes(stored, stored, in.ConnectionPin, kind, f)}
			}
			if kind == KindActive && (o.Answer == "stored" && !sameSets(stored, step.Pins, 0) || o.Answer == "ignored" && f.Has(PinLimitIgnoredCounts)) {
				since = 0
			}
		}
		out = append(out, o)
		stored = o.Stored
	}
	return out, nil
}

// onlyRemoves: every pin of the set is stored in the same kind, so the set only removes pins,
// which a relay with an active key could do in any case.
func onlyRemoves(stored, set Pins) bool {
	for _, p := range set.Active {
		if !slices.Contains(stored.Active, p) {
			return false
		}
	}
	for _, p := range set.Backup {
		if !slices.Contains(stored.Backup, p) {
			return false
		}
	}
	return true
}

// minutesOr returns the minutes given, or for none a day, well beyond the limit.
func minutesOr(minutes *int) int {
	if minutes == nil {
		return minutesPerDay
	}
	return *minutes
}

// overLimit: a new set over a connection with an active pin less than an hour after the last
// set stored over any connection of the gateway with an active pin is ignored; a set that only
// removes pins and a connection with a backup pin have no limit, so that a leaked active key
// cannot hold up the recovery (RELAY-v0 section 4.7).
func overLimit(stored, set Pins, kind Kind, since int, o PinOutcome, f PinFault) bool {
	if f.Has(PinNoLimit) || kind == KindBackup && !f.Has(PinLimitBackup) || o.Answer != "stored" {
		return false
	}
	if sameSets(stored, set, 0) {
		return f.Has(PinLimitEqual) && since < limitMinutes
	}
	if onlyRemoves(stored, set) && !f.Has(PinLimitRemoval) {
		return false
	}
	return since < limitMinutes || f.Has(PinLimitExclusive) && since == limitMinutes
}

// storedElsewhere is the effect on this connection of a set that another control connection
// stored: the set is stored as it is, and this connection is closed if its pin is gone.
func storedElsewhere(before Pins, pin string, kind Kind, set Pins, f PinFault) PinOutcome {
	closed := closes(before, set, pin, kind, f) && !f.Has(PinOtherNoClose) || f.Has(PinOtherAlwaysClose)
	return PinOutcome{"stored", set, closed}
}

// closes reports whether the gateway closes the connection once the set after is stored: its
// pin is no longer stored at all, in either kind.
func closes(before, after Pins, pin string, kind Kind, f PinFault) bool {
	if f.Has(PinNoClose) {
		return false
	}
	probe := after
	if f.Has(PinCloseOldSet) {
		probe = before
	}
	_, present := probe.kindOf(pin)
	if !present {
		return true
	}
	now, _ := after.kindOf(pin)
	return f.Has(PinCloseOnKindChange) && now != kind
}

// Announce decides on one pins message (RELAY-v0 sections 4.7 and 6.8): pin is the pin of the
// connection and kind the kind it had at the handshake.
func Announce(stored Pins, pin string, kind Kind, set Pins, f PinFault) PinOutcome {
	out := answer(stored, pin, kind, set, f)
	out.Closed = closes(stored, out.Stored, pin, kind, f)
	return out
}

// answer decides on a pins message and returns the pins stored afterwards.
func answer(stored Pins, pin string, kind Kind, set Pins, f PinFault) PinOutcome {
	equal := sameSets(stored, set, f)
	switch {
	case equal && !f.Has(PinEqualLast) && !f.Has(PinEqualIgnored):
		return PinOutcome{Answer: "stored", Stored: stored}
	case !acceptable(stored, pin, kind, set, f):
		if f.Has(PinApplyIgnored) {
			return PinOutcome{Answer: "ignored", Stored: set}
		}
		return PinOutcome{Answer: "ignored", Stored: stored}
	case equal && f.Has(PinEqualIgnored):
		return PinOutcome{Answer: "ignored", Stored: stored}
	}
	return PinOutcome{Answer: "stored", Stored: set}
}

func sameSets(a, b Pins, f PinFault) bool {
	if f.Has(PinSwapEqual) {
		return sameSet(slices.Concat(a.Active, a.Backup), slices.Concat(b.Active, b.Backup), f)
	}
	return sameSet(a.Active, b.Active, f) && sameSet(a.Backup, b.Backup, f)
}

func sameSet(a, b []string, f PinFault) bool {
	if f.Has(PinOrderCompare) {
		return slices.Equal(a, b)
	}
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

// acceptable applies the rules of section 6.8 to a set that is not the stored one.
func acceptable(stored Pins, pin string, kind Kind, set Pins, f PinFault) bool {
	if !withinLimits(set, f) {
		return false
	}
	if !f.Has(PinOverlap) && overlap(set) {
		return false
	}
	if f.Has(PinRequireConnPin) && !slices.Contains(set.Active, pin) && !slices.Contains(set.Backup, pin) {
		return false
	}
	if !f.Has(PinNoPinCheck) && !pinKeepsKind(stored, pin, kind, f) {
		return false
	}
	if kind == KindActive {
		return activeRules(stored, set, f)
	}
	return backupRules(stored, set, f)
}

func withinLimits(set Pins, f PinFault) bool {
	limit := maxPins
	if f.Has(PinNine) {
		limit++
	}
	if f.Has(PinSeven) {
		limit--
	}
	if f.Has(PinPerKind) {
		return len(set.Active) <= limit && len(set.Backup) <= limit
	}
	return len(set.Active)+len(set.Backup) <= limit
}

func overlap(set Pins) bool {
	return slices.ContainsFunc(set.Active, func(p string) bool { return slices.Contains(set.Backup, p) })
}

// pinKeepsKind: the pin of the connection is still stored, in the kind it had at the handshake.
func pinKeepsKind(stored Pins, pin string, kind Kind, f PinFault) bool {
	now, ok := stored.kindOf(pin)
	if f.Has(PinKindFromCurrent) {
		return ok
	}
	return ok && now == kind
}

func activeRules(stored, set Pins, f PinFault) bool {
	if len(set.Active) == 0 && !f.Has(PinNullActive) {
		return false
	}
	if f.Has(PinActiveOnlyOne) && len(set.Active) > 1 {
		return false
	}
	return f.Has(PinBackupChange) || sameSet(stored.Backup, set.Backup, f)
}

func backupRules(stored, set Pins, f PinFault) bool {
	if len(set.Active) == 0 && !f.Has(PinNullActive) || len(set.Backup) == 0 && !f.Has(PinNullBackup) {
		return false
	}
	if f.Has(PinBackupKeepsBackup) && !sameSet(stored.Backup, set.Backup, f) {
		return false
	}
	return !f.Has(PinBackupKeepsActive) || sameSet(stored.Active, set.Active, f)
}
