//go:build linux

package nftables

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
)

func testIntervalDecision(id int64, value, duration string) *models.Decision {
	scope, kind, origin, scenario := "Ip", "ban", "crowdsec", "qualification"
	if netipPrefix, err := netip.ParsePrefix(value); err == nil && netipPrefix.IsValid() {
		scope = "Range"
	}
	return &models.Decision{ID: id, Value: &value, Duration: &duration, Scope: &scope,
		Type: &kind, Origin: &origin, Scenario: &scenario}
}

func prepareTest(t *testing.T, state *intervalState, add, deleted []*models.Decision, now time.Time) (*intervalState, []intervalSpan) {
	t.Helper()
	next, spans, err := state.prepare(add, deleted, now)
	if err != nil {
		t.Fatal(err)
	}
	return next, spans
}

func TestIntervalsPreserveCIDRAndExactFamilyBoundaries(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	for _, item := range []struct{ value, first, last string }{
		{"198.51.100.8/30", "198.51.100.8", "198.51.100.11"},
		{"fd00:767::8/126", "fd00:767::8", "fd00:767::b"},
		{"0.0.0.0/0", "0.0.0.0", "255.255.255.255"},
		{"::/0", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"255.255.255.255", "255.255.255.255", "255.255.255.255"},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
	} {
		t.Run(item.value, func(t *testing.T) {
			_, spans := prepareTest(t, newIntervalState(), []*models.Decision{testIntervalDecision(1, item.value, "1h")}, nil, now)
			want := []intervalSpan{{netip.MustParseAddr(item.first), netip.MustParseAddr(item.last), now.Add(time.Hour)}}
			if !reflect.DeepEqual(spans, want) {
				t.Fatalf("CIDR changed: got %#v want %#v", spans, want)
			}
		})
	}
}

func TestIntervalsOverlapsUseLatestExpiryWithoutBroadening(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	state, spans := prepareTest(t, newIntervalState(), []*models.Decision{
		testIntervalDecision(1, "198.51.100.8/30", "1h"),
		testIntervalDecision(2, "198.51.100.9", "2h"),
	}, nil, now)
	want := []intervalSpan{
		{netip.MustParseAddr("198.51.100.8"), netip.MustParseAddr("198.51.100.8"), now.Add(time.Hour)},
		{netip.MustParseAddr("198.51.100.9"), netip.MustParseAddr("198.51.100.9"), now.Add(2 * time.Hour)},
		{netip.MustParseAddr("198.51.100.10"), netip.MustParseAddr("198.51.100.11"), now.Add(time.Hour)},
	}
	if !reflect.DeepEqual(spans, want) {
		t.Fatalf("overlap expiry changed: got %#v want %#v", spans, want)
	}
	_, spans = prepareTest(t, state, nil, []*models.Decision{{ID: 1}}, now.Add(time.Minute))
	if !reflect.DeepEqual(spans, want[1:2]) {
		t.Fatalf("revoke removed another owner or retained revoked range: %#v", spans)
	}
}

func TestIntervalsExpiredOwnersAndReplayNeverRenew(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	state, _ := prepareTest(t, newIntervalState(), []*models.Decision{testIntervalDecision(1, "198.51.100.8/30", "10s")}, nil, now)
	state, spans := prepareTest(t, state, []*models.Decision{testIntervalDecision(1, "198.51.100.8/30", "1h")}, nil, now.Add(5*time.Second))
	if len(spans) != 1 || !spans[0].until.Equal(now.Add(10*time.Second)) {
		t.Fatalf("replay renewed expiry: %#v", spans)
	}
	state, spans = prepareTest(t, state, nil, nil, now.Add(11*time.Second))
	if len(spans) != 0 {
		t.Fatalf("expired range survived empty commit: %#v", spans)
	}
}

func TestIntervalsIDOnlyDeleteWinsSameBatchAndDelayedCreate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	decision := testIntervalDecision(1, "fd00:767::8/126", "1h")
	state, spans := prepareTest(t, newIntervalState(), []*models.Decision{decision}, []*models.Decision{{ID: 1}}, now)
	if len(spans) != 0 {
		t.Fatalf("same-batch create overrode deletion: %#v", spans)
	}
	_, spans = prepareTest(t, state, []*models.Decision{decision}, nil, now.Add(time.Minute))
	if len(spans) != 0 {
		t.Fatalf("delayed create overrode tombstone: %#v", spans)
	}
}

func TestIntervalsMalformedBatchAndChangedIDAreAtomic(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	state, before := prepareTest(t, newIntervalState(), []*models.Decision{testIntervalDecision(1, "198.51.100.8/30", "1h")}, nil, now)
	for _, invalid := range []*models.Decision{
		nil, {ID: 4}, testIntervalDecision(0, "198.51.100.9", "1h"),
		testIntervalDecision(4, "198.51.100.9/30", "1h"),
		testIntervalDecision(4, "fe80::1%wan", "1h"),
		testIntervalDecision(4, "::ffff:192.0.2.0/120", "1h"),
		testIntervalDecision(4, "198.51.100.9", "bad"),
		testIntervalDecision(1, "198.51.100.12/30", "1h"),
	} {
		if _, _, err := state.prepare([]*models.Decision{testIntervalDecision(3, "198.51.100.20", "1h"), invalid}, []*models.Decision{{ID: 1}}, now); err == nil {
			t.Fatalf("invalid decision accepted: %#v", invalid)
		}
		_, after := prepareTest(t, state, nil, nil, now)
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("invalid batch changed committed state: %#v", after)
		}
	}
}

func TestIntervalsActiveCapRefusesWithoutDroppingLiveOwners(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	state, before := prepareTest(t, newIntervalState(), []*models.Decision{testIntervalDecision(1, "198.51.100.8", "1h")}, nil, now)
	for id := int64(2); id <= maxIntervalActive; id++ {
		state.decisions[id] = state.decisions[1]
	}
	if _, _, err := state.prepare([]*models.Decision{testIntervalDecision(maxIntervalActive+1, "198.51.100.9", "1h")}, nil, now); err == nil {
		t.Fatal("full active state silently admitted another ID")
	}
	_, after := prepareTest(t, state, nil, nil, now)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("capacity error dropped live state")
	}
}

func TestIntervalsTombstonesEndAtOriginalExpiryAndUnknownDeletesDoNotAccumulate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	state, _ := prepareTest(t, newIntervalState(), []*models.Decision{testIntervalDecision(1, "198.51.100.8", "10s")}, nil, now)
	state, _ = prepareTest(t, state, nil, []*models.Decision{{ID: 1}, {ID: 2}}, now.Add(time.Second))
	if len(state.retired) != 1 || !state.retired[1].Equal(now.Add(10*time.Second)) {
		t.Fatalf("unexpected revocation history: %#v", state.retired)
	}
	state, _ = prepareTest(t, state, nil, nil, now.Add(11*time.Second))
	if len(state.retired) != 0 || len(state.decisions) != 0 {
		t.Fatal("expired history was not reclaimed")
	}
}

func TestIntervalsUnsupportedRemediationDoesNotPreventValidBan(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	captcha := testIntervalDecision(2, "198.51.100.20", "1h")
	kind := "captcha"
	captcha.Type, captcha.Duration = &kind, nil
	state, spans := prepareTest(t, newIntervalState(), []*models.Decision{
		testIntervalDecision(1, "198.51.100.8/30", "1h"), captcha,
	}, nil, now)
	if len(spans) != 1 || spans[0].first.String() != "198.51.100.8" || spans[0].last.String() != "198.51.100.11" {
		t.Fatalf("unsupported remediation prevented valid ban: %#v", spans)
	}
	_, after := prepareTest(t, state, nil, []*models.Decision{captcha}, now)
	if !reflect.DeepEqual(spans, after) {
		t.Fatalf("unsupported delete changed valid bans: %#v", after)
	}
}

func TestIntervalsElapsedSourceDurationDoesNotDiscardFreshBans(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	state, spans := prepareTest(t, newIntervalState(), []*models.Decision{
		testIntervalDecision(1, "198.51.100.0/30", "0s"),
		testIntervalDecision(2, "198.51.100.4/30", "-1s"),
		testIntervalDecision(3, "198.51.100.8/30", "1h"),
	}, nil, now)
	if len(state.decisions) != 1 || len(spans) != 1 || spans[0].first.String() != "198.51.100.8" || spans[0].last.String() != "198.51.100.11" {
		t.Fatalf("rounded/elapsed source entry discarded fresh ban: %#v", spans)
	}
	_, spans = prepareTest(t, state, []*models.Decision{
		testIntervalDecision(3, "198.51.100.8/30", "0s"),
		testIntervalDecision(4, "198.51.100.12/30", "1h"),
	}, nil, now.Add(time.Minute))
	if len(spans) != 1 || spans[0].first.String() != "198.51.100.12" {
		t.Fatalf("elapsed existing owner survived or prevented new owner: %#v", spans)
	}
}

func TestIntervalCleanupPreservesKernelTimeoutsAndCommittedOwners(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprintf("failed_commit_%t", failed), func(t *testing.T) {
			messages := 0
			conn, err := nftables.New(nftables.WithTestDial(func(request []netlink.Message) ([]netlink.Message, error) {
				messages += len(request)
				return request, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			table := &nftables.Table{Name: "praho_crowdsec4", Family: nftables.TableFamilyIPv4}
			set := &nftables.Set{Name: "bans", Table: table, Interval: true, HasTimeout: true}
			state, _ := prepareTest(t, newIntervalState(), []*models.Decision{testIntervalDecision(1, "198.51.100.8/30", "1h")}, nil, time.Now())
			backend := &nft{intervals: state,
				v4: &nftContext{conn: conn, table: table, blacklists: "bans", sets: map[string]*nftables.Set{"bans": set}, setOnly: true},
				v6: &nftContext{},
			}
			if failed {
				backend.Add(testIntervalDecision(2, "198.51.100.9/30", "1h"))
				if err := backend.Commit(); err == nil {
					t.Fatal("invalid frame unexpectedly committed")
				}
				if len(backend.intervals.decisions) != 1 {
					t.Fatal("failed frame discarded existing owners")
				}
			}
			if err := backend.ShutDown(); err != nil {
				t.Fatal(err)
			}
			if messages != 0 {
				t.Fatalf("interval cleanup flushed live kernel timeout sets: %d netlink messages", messages)
			}
		})
	}
}

func TestIntervalsSweepMatchesIndependentSmallAddressOracle(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var decisions []*models.Decision
	expected := make(map[netip.Addr]time.Time)
	for index := 0; index < 64; index++ {
		width, bits := 4, 30
		if index%3 == 0 {
			width, bits = 8, 29
		}
		start := ((index * 37) % 16) * 8
		prefix := fmt.Sprintf("198.51.100.%d/%d", start, bits)
		duration := time.Duration(index%7+1) * time.Minute
		decisions = append(decisions, testIntervalDecision(int64(index+1), prefix, duration.String()))
		for offset := 0; offset < width; offset++ {
			address := netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", start+offset))
			if until := now.Add(duration); until.After(expected[address]) {
				expected[address] = until
			}
		}
	}
	_, spans := prepareTest(t, newIntervalState(), decisions, nil, now)
	for number := 0; number < 256; number++ {
		address := netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", number))
		var actual time.Time
		for _, span := range spans {
			if span.first.Compare(address) <= 0 && span.last.Compare(address) >= 0 {
				if !actual.IsZero() {
					t.Fatalf("overlapping output segments at %s", address)
				}
				actual = span.until
			}
		}
		if !actual.Equal(expected[address]) {
			t.Fatalf("address %s expiry mismatch: %v want %v", address, actual, expected[address])
		}
	}
}
