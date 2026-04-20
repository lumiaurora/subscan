package resolver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultLookupTimeout = 5 * time.Second
	defaultWorkerCount   = 20
	wildcardSamples      = 2
)

type Options struct {
	Workers       int
	LookupTimeout time.Duration
	TargetDomain  string
	LookupHost    func(context.Context, string) ([]string, error)
	RandomLabel   func() string
}

type Result struct {
	Live              []string
	WildcardFiltered  int
	WildcardProtected []string
}

type lookupResult struct {
	index     int
	addresses []string
	live      bool
}

type wildcardResult struct {
	active     bool
	signatures map[string]struct{}
}

func ResolveSubdomains(subdomains []string, options Options) Result {
	if len(subdomains) == 0 {
		return Result{}
	}

	lookupTimeout := options.LookupTimeout
	if lookupTimeout <= 0 {
		lookupTimeout = defaultLookupTimeout
	}

	lookupHost := options.LookupHost
	if lookupHost == nil {
		resolver := net.Resolver{}
		lookupHost = resolver.LookupHost
	}

	jobs := make(chan int)
	results := make(chan lookupResult, len(subdomains))

	workers := options.Workers
	if workers <= 0 {
		workers = defaultWorkerCount
	}
	if len(subdomains) < workers {
		workers = len(subdomains)
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for index := range jobs {
				ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
				addresses, err := lookupHost(ctx, subdomains[index])
				cancel()

				results <- lookupResult{index: index, addresses: normalizeAddresses(addresses), live: err == nil && len(addresses) > 0}
			}
		}()
	}

	go func() {
		for index := range subdomains {
			jobs <- index
		}
		close(jobs)

		wg.Wait()
		close(results)
	}()

	resolved := make(map[int][]string, len(subdomains))
	for result := range results {
		if result.live {
			resolved[result.index] = result.addresses
		}
	}

	if options.TargetDomain == "" {
		live := make([]string, 0, len(resolved))
		for index, subdomain := range subdomains {
			if _, ok := resolved[index]; ok {
				live = append(live, subdomain)
			}
		}

		return Result{Live: live}
	}

	randomLabel := options.RandomLabel
	if randomLabel == nil {
		randomLabel = generateRandomLabel
	}

	cache := make(map[string]wildcardResult)
	live := make([]string, 0, len(resolved))
	protected := make([]string, 0)

	for index, subdomain := range subdomains {
		addresses, ok := resolved[index]
		if !ok {
			continue
		}

		if wildcardOnly(subdomain, addresses, options.TargetDomain, lookupTimeout, lookupHost, randomLabel, cache) {
			protected = append(protected, subdomain)
			continue
		}

		live = append(live, subdomain)
	}

	return Result{
		Live:              live,
		WildcardFiltered:  len(protected),
		WildcardProtected: protected,
	}
}

func wildcardOnly(host string, addresses []string, targetDomain string, lookupTimeout time.Duration, lookupHost func(context.Context, string) ([]string, error), randomLabel func() string, cache map[string]wildcardResult) bool {
	for _, zone := range candidateWildcardZones(host, targetDomain) {
		result, ok := cache[zone]
		if !ok {
			result = detectWildcard(zone, lookupTimeout, lookupHost, randomLabel)
			cache[zone] = result
		}

		if !result.active {
			continue
		}

		if _, ok := result.signatures[addressSignature(addresses)]; ok {
			return true
		}
	}

	return false
}

func candidateWildcardZones(host string, targetDomain string) []string {
	host = strings.ToLower(strings.TrimSpace(host))
	targetDomain = strings.ToLower(strings.TrimSpace(targetDomain))

	hostLabels := strings.Split(host, ".")
	targetLabels := strings.Split(targetDomain, ".")
	if len(hostLabels) <= len(targetLabels) {
		return nil
	}

	zones := make([]string, 0, len(hostLabels)-len(targetLabels))
	for index := 1; index <= len(hostLabels)-len(targetLabels); index++ {
		zone := strings.Join(hostLabels[index:], ".")
		if zone == targetDomain || strings.HasSuffix(zone, "."+targetDomain) {
			zones = append(zones, zone)
		}
	}

	return zones
}

func detectWildcard(zone string, lookupTimeout time.Duration, lookupHost func(context.Context, string) ([]string, error), randomLabel func() string) wildcardResult {
	signatures := make(map[string]struct{}, wildcardSamples)
	resolvedSamples := 0

	for sample := 0; sample < wildcardSamples; sample++ {
		host := randomLabel() + "." + zone
		ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
		addresses, err := lookupHost(ctx, host)
		cancel()
		if err != nil || len(addresses) == 0 {
			continue
		}

		resolvedSamples++
		signatures[addressSignature(normalizeAddresses(addresses))] = struct{}{}
	}

	return wildcardResult{
		active:     resolvedSamples == wildcardSamples,
		signatures: signatures,
	}
}

func normalizeAddresses(addresses []string) []string {
	if len(addresses) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(addresses))
	normalized := make([]string, 0, len(addresses))
	for _, address := range addresses {
		address = strings.TrimSpace(strings.ToLower(address))
		if address == "" {
			continue
		}

		if _, ok := seen[address]; ok {
			continue
		}

		seen[address] = struct{}{}
		normalized = append(normalized, address)
	}

	sort.Strings(normalized)
	return normalized
}

func addressSignature(addresses []string) string {
	return strings.Join(normalizeAddresses(addresses), ",")
}

func generateRandomLabel() string {
	buffer := make([]byte, 8)
	if _, err := rand.Read(buffer); err != nil {
		return "subscan-random"
	}

	return "subscan-" + hex.EncodeToString(buffer)
}
