package ad

import "testing"

func TestResolveDomainExplicit(t *testing.T) {
	got, err := ResolveDomain("Example.COM.", "")
	if err != nil {
		t.Fatalf("ResolveDomain returned error: %v", err)
	}
	if want := "example.com"; got != want {
		t.Fatalf("ResolveDomain explicit: want %q, got %q", want, got)
	}
}

func TestResolveDomainFromUsername(t *testing.T) {
	got, err := ResolveDomain("", "alice@Sub.Example.COM.")
	if err != nil {
		t.Fatalf("ResolveDomain from username returned error: %v", err)
	}
	if want := "sub.example.com"; got != want {
		t.Fatalf("ResolveDomain from username: want %q, got %q", want, got)
	}
}

func TestResolveDomainFromEnv(t *testing.T) {
	t.Setenv("DISCOVR_AD_DOMAIN", "CORP.INTERNAL.")
	got, err := ResolveDomain("", "")
	if err != nil {
		t.Fatalf("ResolveDomain from env returned error: %v", err)
	}
	if want := "corp.internal"; got != want {
		t.Fatalf("ResolveDomain from env: want %q, got %q", want, got)
	}
}

func TestResolveDomainPrefersUsernameOverEnv(t *testing.T) {
	t.Setenv("DISCOVR_AD_DOMAIN", "corp.internal")
	got, err := ResolveDomain("", "DOMAIN\\alice")
	if err != nil {
		t.Fatalf("ResolveDomain from username with env returned error: %v", err)
	}
	if want := "domain"; got != want {
		t.Fatalf("ResolveDomain preference mismatch: want %q, got %q", want, got)
	}
}

func TestResolveDomainError(t *testing.T) {
	t.Setenv("DISCOVR_AD_DOMAIN", "")
	t.Setenv("USERDNSDOMAIN", "")
	t.Setenv("USERDOMAIN", "")
	if _, err := ResolveDomain("", "alice"); err == nil {
		t.Fatalf("ResolveDomain should error when domain cannot be determined")
	}
}

func TestDomainToBase(t *testing.T) {
	got := domainToBase("corp.Example.COM.")
	want := "DC=corp,DC=Example,DC=COM"
	if got != want {
		t.Fatalf("domainToBase mismatch: want %q, got %q", want, got)
	}
}

func TestFormatBindUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		domain   string
		want     string
	}{
		{"append domain", "alice", "example.com", "alice@example.com"},
		{"keep upn", "alice@example.com", "example.com", "alice@example.com"},
		{"keep netbios", "DOMAIN\\alice", "example.com", "DOMAIN\\alice"},
		{"no domain", "alice", "", "alice"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatBindUsername(tc.username, tc.domain); got != tc.want {
				t.Fatalf("formatBindUsername %s: want %q, got %q", tc.name, tc.want, got)
			}
		})
	}
}
