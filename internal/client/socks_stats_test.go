package client

import (
	"strings"
	"testing"
	"time"
)

func TestSocksStatsReportsQuantilesAndDistribution(t *testing.T) {
	t.Parallel()

	var s socksStats
	for _, ms := range []int{50, 90, 120, 300, 380, 700, 1500, 4000} {
		s.recordOpen(time.Duration(ms) * time.Millisecond)
	}
	s.recordFailure()

	samples, failures, dropped := s.drain()
	line := formatSocksWindow(samples, failures, dropped)

	for _, want := range []string{"n=8", "failed=1", "p50=", "p90=", "max=4s", "0-100ms:2", ">3000ms:1"} {
		if !strings.Contains(line, want) {
			t.Errorf("line %q missing %q", line, want)
		}
	}
}

func TestSocksStatsDrainResetsWindow(t *testing.T) {
	t.Parallel()

	var s socksStats
	s.recordOpen(100 * time.Millisecond)
	s.recordFailure()
	s.drain()

	samples, failures, dropped := s.drain()
	if len(samples) != 0 || failures != 0 || dropped != 0 {
		t.Fatalf("window not reset: samples=%d failures=%d dropped=%d", len(samples), failures, dropped)
	}
}

// The window must stay bounded even if something opens connections in a tight
// loop; the count still has to be reported honestly.
func TestSocksStatsBoundsSamplesButCountsThem(t *testing.T) {
	t.Parallel()

	var s socksStats
	for range socksSamplesCap + 100 {
		s.recordOpen(time.Millisecond)
	}
	samples, _, dropped := s.drain()
	if len(samples) != socksSamplesCap {
		t.Errorf("samples = %d, want %d", len(samples), socksSamplesCap)
	}
	if dropped != 100 {
		t.Errorf("dropped = %d, want 100", dropped)
	}
}

func TestRoundMillisGivesMillisecondResolution(t *testing.T) {
	t.Parallel()

	// The old client log carried whole seconds, which is what made a median of
	// "2 s" impossible to act on.
	got := roundMillis(412 * time.Millisecond).String()
	if got != "412ms" {
		t.Fatalf("roundMillis = %q, want %q", got, "412ms")
	}
}
