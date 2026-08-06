package subscription

import (
	"testing"
	"time"
)

func TestParseRefreshInterval(t *testing.T) {
	if got := ParseRefreshInterval(""); got != 10*time.Minute {
		t.Fatalf("default = %v", got)
	}
	if got := ParseRefreshInterval("5m"); got != 5*time.Minute {
		t.Fatalf("5m = %v", got)
	}
	if got := ParseRefreshInterval("bogus"); got != 10*time.Minute {
		t.Fatalf("bogus = %v", got)
	}
}
