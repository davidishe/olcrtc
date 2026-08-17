package client

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/logger"
)

// socksStatsInterval is how often the aggregate line is emitted. It matches the
// KCP telemetry interval in turnrelay so the two can be read against each other
// in a single diagnostic batch.
const socksStatsInterval = 10 * time.Second

// socksSamplesCap bounds the per-window sample slice. A browsing session opens
// far fewer than this in ten seconds; the cap only guards a pathological burst
// from growing the slice without limit.
const socksSamplesCap = 4096

// socksStats accumulates connection-setup latencies and reports them as one
// line per window. The plan's acceptance criteria are stated as median, p90 and
// a per-second distribution, so those are exactly what gets logged — no
// post-processing of individual lines required to answer "is it better now".
type socksStats struct {
	mu       sync.Mutex
	samples  []time.Duration
	failures int
	dropped  int
}

func (s *socksStats) recordOpen(d time.Duration) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if len(s.samples) < socksSamplesCap {
		s.samples = append(s.samples, d)
	} else {
		s.dropped++
	}
	s.mu.Unlock()
}

func (s *socksStats) recordFailure() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.failures++
	s.mu.Unlock()
}

// drain takes the current window and resets the accumulator.
func (s *socksStats) drain() (samples []time.Duration, failures, dropped int) {
	s.mu.Lock()
	samples, failures, dropped = s.samples, s.failures, s.dropped
	s.samples, s.failures, s.dropped = nil, 0, 0
	s.mu.Unlock()
	return samples, failures, dropped
}

// reportLoop emits one aggregate line per interval until ctx ends. Windows with
// no activity are skipped: an idle tunnel should be quiet in the log.
func (s *socksStats) reportLoop(done <-chan struct{}) {
	ticker := time.NewTicker(socksStatsInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			samples, failures, dropped := s.drain()
			if len(samples) == 0 && failures == 0 {
				continue
			}
			logger.Infof("socks: opens %s", formatSocksWindow(samples, failures, dropped))
		}
	}
}

func formatSocksWindow(samples []time.Duration, failures, dropped int) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("n=%d failed=%d", len(samples), failures))
	if dropped > 0 {
		b.WriteString(fmt.Sprintf(" unsampled=%d", dropped))
	}
	if len(samples) == 0 {
		return b.String()
	}

	sorted := make([]time.Duration, len(samples))
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	b.WriteString(fmt.Sprintf(" p50=%s p90=%s max=%s",
		roundMillis(quantile(sorted, 0.50)),
		roundMillis(quantile(sorted, 0.90)),
		roundMillis(sorted[len(sorted)-1])))
	b.WriteString(" dist=" + formatBuckets(sorted))
	return b.String()
}

// quantile returns the nearest-rank quantile of an ascending slice.
func quantile(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(q * float64(len(sorted)))
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// socksBuckets are upper bounds in milliseconds. The boundaries are chosen
// around the plan's targets — under 400 ms is the goal, over 1 s is the
// behaviour users complain about — so the shape of the problem is readable
// straight off the line.
var socksBuckets = []int64{100, 250, 400, 1000, 3000}

func formatBuckets(sorted []time.Duration) string {
	counts := make([]int, len(socksBuckets)+1)
	for _, d := range sorted {
		ms := d.Milliseconds()
		placed := false
		for i, bound := range socksBuckets {
			if ms <= bound {
				counts[i]++
				placed = true
				break
			}
		}
		if !placed {
			counts[len(counts)-1]++
		}
	}

	parts := make([]string, 0, len(counts))
	prev := int64(0)
	for i, bound := range socksBuckets {
		parts = append(parts, fmt.Sprintf("%d-%dms:%d", prev, bound, counts[i]))
		prev = bound
	}
	parts = append(parts, fmt.Sprintf(">%dms:%d", prev, counts[len(counts)-1]))
	return strings.Join(parts, " ")
}

// roundMillis renders a duration at millisecond resolution. The old client log
// carried whole seconds, which made a median of "2 s" impossible to act on.
func roundMillis(d time.Duration) time.Duration {
	return d.Round(time.Millisecond)
}
