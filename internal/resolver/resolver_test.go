package resolver

import (
	"context"
	"net"
	"slices"
	"testing"
)

func TestResolveSubdomainsFiltersWildcardHosts(t *testing.T) {
	lookups := map[string][]string{
		"ghost.example.com":  {"1.1.1.1"},
		"real.example.com":   {"2.2.2.2"},
		"wild-a.example.com": {"1.1.1.1"},
		"wild-b.example.com": {"1.1.1.1"},
	}
	labels := []string{"wild-a", "wild-b"}
	labelIndex := 0

	result := ResolveSubdomains([]string{"ghost.example.com", "real.example.com"}, Options{
		TargetDomain: "example.com",
		LookupHost: func(ctx context.Context, host string) ([]string, error) {
			if addresses, ok := lookups[host]; ok {
				return addresses, nil
			}

			return nil, &net.DNSError{IsNotFound: true}
		},
		RandomLabel: func() string {
			label := labels[labelIndex]
			labelIndex++
			return label
		},
	})

	if !slices.Equal(result.Live, []string{"real.example.com"}) {
		t.Fatalf("expected only real.example.com to survive, got %v", result.Live)
	}

	if result.WildcardFiltered != 1 {
		t.Fatalf("expected one wildcard-filtered hostname, got %d", result.WildcardFiltered)
	}

	if !slices.Equal(result.WildcardProtected, []string{"ghost.example.com"}) {
		t.Fatalf("unexpected wildcard-protected hosts: %v", result.WildcardProtected)
	}

	if got := result.Details["real.example.com"].IPs; !slices.Equal(got, []string{"2.2.2.2"}) {
		t.Fatalf("unexpected IP details for real.example.com: %v", got)
	}
}

func TestResolveSubdomainsWithoutTargetDomainSkipsWildcardChecks(t *testing.T) {
	result := ResolveSubdomains([]string{"one.example.com"}, Options{
		LookupHost: func(ctx context.Context, host string) ([]string, error) {
			return []string{"1.1.1.1"}, nil
		},
		LookupCNAME: func(ctx context.Context, host string) (string, error) {
			return "edge.example.net.", nil
		},
	})

	if !slices.Equal(result.Live, []string{"one.example.com"}) {
		t.Fatalf("expected hostname to remain live, got %v", result.Live)
	}

	if result.WildcardFiltered != 0 {
		t.Fatalf("expected no wildcard filtering without target domain")
	}

	detail := result.Details["one.example.com"]
	if !slices.Equal(detail.IPs, []string{"1.1.1.1"}) {
		t.Fatalf("unexpected IPs: %v", detail.IPs)
	}

	if !slices.Equal(detail.CNAMEs, []string{"edge.example.net"}) {
		t.Fatalf("unexpected CNAMEs: %v", detail.CNAMEs)
	}
}
