package turnrelay

import "testing"

func TestParseTurnURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in       string
		wantHost string
		wantPort string
	}{
		{"turn:turn.example:3478", "turn.example", "3478"},
		{"turn:turn.example:3478?transport=udp", "turn.example", "3478"},
		{"turns:turn.example:5349", "turn.example", "5349"},
		{"turn.example", "turn.example", "3478"},
		{"1.2.3.4:3478", "1.2.3.4", "3478"},
	}
	for _, tc := range cases {
		host, port, err := parseTurnURL(tc.in)
		if err != nil {
			t.Fatalf("parseTurnURL(%q): %v", tc.in, err)
		}
		if host != tc.wantHost || port != tc.wantPort {
			t.Errorf("parseTurnURL(%q)=%s:%s want %s:%s", tc.in, host, port, tc.wantHost, tc.wantPort)
		}
	}
}

func TestPickTurnHostPortPrefersUDP(t *testing.T) {
	t.Parallel()
	host, port, err := pickTurnHostPort([]string{
		"turns:secure.example:5349",
		"turn:plain.example:3478?transport=udp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if host != "plain.example" || port != "3478" {
		t.Fatalf("got %s:%s", host, port)
	}
}
