package turnrelay

import (
	"strings"
	"testing"
)

func TestFormatSnmpDeltaReportsLossAndFECUsefulness(t *testing.T) {
	t.Parallel()

	d := snmpSample{
		outSegs:   1000,
		inSegs:    800,
		outBytes:  1_400_000,
		inBytes:   900_000,
		sent:      1_000_000,
		received:  850_000,
		retrans:   25,
		fastRe:    10,
		lost:      20,
		fecRecov:  0,
		fecParity: 300,
	}

	line := formatSnmpDelta(d, " srtt=142ms rto=300ms")

	// The two questions the plan needs answered: how lossy is the path, and is
	// FEC recovering anything for the redundancy it costs.
	for _, want := range []string{
		"retrans=25(2.50%)",
		"lost=20(2.00%)",
		"fec=recovered:0/errs:0/parity:300",
		"overhead=up:1.40x",
		"srtt=142ms",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("line %q missing %q", line, want)
		}
	}
}

// A window with no traffic must say so rather than print ratios over zero —
// ten seconds of silence is itself the symptom we are hunting.
func TestFormatSnmpDeltaMarksIdleWindow(t *testing.T) {
	t.Parallel()

	line := formatSnmpDelta(snmpSample{}, "")
	if !strings.Contains(line, "idle") {
		t.Fatalf("line %q does not mark the window idle", line)
	}
	if strings.Contains(line, "NaN") || strings.Contains(line, "+Inf") {
		t.Fatalf("line %q divided by zero", line)
	}
}

func TestSubClampsCountersThatWentBackwards(t *testing.T) {
	t.Parallel()

	now := snmpSample{outSegs: 5}
	prev := snmpSample{outSegs: 10}
	if got := now.sub(prev).outSegs; got != 0 {
		t.Fatalf("outSegs = %d, want 0 after a counter reset", got)
	}
}

func TestKCPMTUStaysUnderThePathCeiling(t *testing.T) {
	t.Parallel()

	// Fragmented UDP is lost whole, so the configured MTU must never exceed
	// what the worst expected path can carry after TURN/UDP/IP overhead.
	if kcpMTU > kcpMTUCeiling {
		t.Fatalf("kcpMTU = %d exceeds the path ceiling %d", kcpMTU, kcpMTUCeiling)
	}
}
