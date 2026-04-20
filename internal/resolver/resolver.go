package resolver

import (
	"context"
	"net"
	"sync"
	"time"
)

const (
	defaultLookupTimeout = 5 * time.Second
	defaultWorkerCount   = 20
)

type Options struct {
	Workers       int
	LookupTimeout time.Duration
}

type lookupResult struct {
	index int
	live  bool
}

func ResolveSubdomains(subdomains []string, options Options) []string {
	if len(subdomains) == 0 {
		return nil
	}

	lookupTimeout := options.LookupTimeout
	if lookupTimeout <= 0 {
		lookupTimeout = defaultLookupTimeout
	}

	jobs := make(chan int)
	results := make(chan lookupResult, len(subdomains))
	resolver := net.Resolver{}

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
				_, err := resolver.LookupHost(ctx, subdomains[index])
				cancel()

				results <- lookupResult{index: index, live: err == nil}
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

	liveSet := make(map[int]struct{}, len(subdomains))
	for result := range results {
		if result.live {
			liveSet[result.index] = struct{}{}
		}
	}

	live := make([]string, 0, len(liveSet))
	for index, subdomain := range subdomains {
		if _, ok := liveSet[index]; ok {
			live = append(live, subdomain)
		}
	}

	return live
}
