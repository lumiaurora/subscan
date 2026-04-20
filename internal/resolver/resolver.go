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
	LookupCNAME   func(context.Context, string) (string, error)
	RandomLabel   func() string
}

type Resolution struct {
	IPs    []string
	CNAMEs []string
}

type Result struct {
	Live              []string
	Details           map[string]Resolution
	WildcardFiltered  int
	WildcardProtected []string
}

type lookupResult struct {
	index      int
	resolution Resolution
	live       bool
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
	lookupCNAME := options.LookupCNAME
	if lookupHost == nil {
		defaultResolver := net.Resolver{}
		lookupHost = defaultResolver.LookupHost
		lookupCNAME = defaultResolver.LookupCNAME
	} else if lookupCNAME == nil {
		defaultResolver := net.Resolver{}
		lookupCNAME = defaultResolver.LookupCNAME
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
				resolution, live := resolveHost(subdomains[index], lookupTimeout, lookupHost, lookupCNAME)
				results <- lookupResult{index: index, resolution: resolution, live: live}
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

	resolved := make(map[int]Resolution, len(subdomains))
	for result := range results {
		if result.live {
			resolved[result.index] = result.resolution
		}
	}

	if options.TargetDomain == "" {
		live := make([]string, 0, len(resolved))
		details := make(map[string]Resolution, len(resolved))
		for index, subdomain := range subdomains {
			if resolution, ok := resolved[index]; ok {
				live = append(live, subdomain)
				details[subdomain] = resolution
			}
		}

		return Result{Live: live, Details: details}
	}

	randomLabel := options.RandomLabel
	if randomLabel == nil {
		randomLabel = generateRandomLabel
	}

	cache := make(map[string]wildcardResult)
	live := make([]string, 0, len(resolved))
	details := make(map[string]Resolution, len(resolved))
	protected := make([]string, 0)

	for index, subdomain := range subdomains {
		resolution, ok := resolved[index]
		if !ok {
			continue
		}

		if wildcardOnly(subdomain, resolution, options.TargetDomain, lookupTimeout, lookupHost, lookupCNAME, randomLabel, cache) {
			protected = append(protected, subdomain)
			continue
		}

		live = append(live, subdomain)
		details[subdomain] = resolution
	}

	return Result{
		Live:              live,
		Details:           details,
		WildcardFiltered:  len(protected),
		WildcardProtected: protected,
	}
}

func resolveHost(host string, lookupTimeout time.Duration, lookupHost func(context.Context, string) ([]string, error), lookupCNAME func(context.Context, string) (string, error)) (Resolution, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	addresses, err := lookupHost(ctx, host)
	cancel()
	if err != nil || len(addresses) == 0 {
		return Resolution{}, false
	}

	resolution := Resolution{IPs: normalizeValues(addresses)}
	resolution.CNAMEs = lookupCanonicalNames(host, lookupTimeout, lookupCNAME)
	return resolution, true
}

func wildcardOnly(host string, resolution Resolution, targetDomain string, lookupTimeout time.Duration, lookupHost func(context.Context, string) ([]string, error), lookupCNAME func(context.Context, string) (string, error), randomLabel func() string, cache map[string]wildcardResult) bool {
	for _, zone := range candidateWildcardZones(host, targetDomain) {
		result, ok := cache[zone]
		if !ok {
			result = detectWildcard(zone, lookupTimeout, lookupHost, lookupCNAME, randomLabel)
			cache[zone] = result
		}

		if !result.active {
			continue
		}

		if _, ok := result.signatures[resolutionSignature(resolution)]; ok {
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

func detectWildcard(zone string, lookupTimeout time.Duration, lookupHost func(context.Context, string) ([]string, error), lookupCNAME func(context.Context, string) (string, error), randomLabel func() string) wildcardResult {
	signatures := make(map[string]struct{}, wildcardSamples)
	resolvedSamples := 0

	for sample := 0; sample < wildcardSamples; sample++ {
		host := randomLabel() + "." + zone
		resolution, live := resolveHost(host, lookupTimeout, lookupHost, lookupCNAME)
		if !live {
			continue
		}

		resolvedSamples++
		signatures[resolutionSignature(resolution)] = struct{}{}
	}

	return wildcardResult{
		active:     resolvedSamples == wildcardSamples,
		signatures: signatures,
	}
}

func lookupCanonicalNames(host string, lookupTimeout time.Duration, lookupCNAME func(context.Context, string) (string, error)) []string {
	if lookupCNAME == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	cname, err := lookupCNAME(ctx, host)
	cancel()
	if err != nil {
		return nil
	}

	cname = strings.TrimSpace(strings.TrimSuffix(strings.ToLower(cname), "."))
	host = strings.TrimSpace(strings.TrimSuffix(strings.ToLower(host), "."))
	if cname == "" || cname == host {
		return nil
	}

	return []string{cname}
}

func normalizeValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(strings.TrimSuffix(value, ".")))
		if value == "" {
			continue
		}

		if _, ok := seen[value]; ok {
			continue
		}

		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}

	sort.Strings(normalized)
	return normalized
}

func resolutionSignature(resolution Resolution) string {
	return strings.Join(resolution.IPs, ",") + "|" + strings.Join(resolution.CNAMEs, ",")
}

func generateRandomLabel() string {
	buffer := make([]byte, 8)
	if _, err := rand.Read(buffer); err != nil {
		return "subscan-random"
	}

	return "subscan-" + hex.EncodeToString(buffer)
}
