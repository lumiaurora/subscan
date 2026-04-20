package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lumiaurora/subscan/internal/config"
	"github.com/lumiaurora/subscan/internal/output"
	"github.com/lumiaurora/subscan/internal/resolver"
	"github.com/lumiaurora/subscan/internal/sources"
	"github.com/lumiaurora/subscan/internal/utils"
)

const (
	defaultThreads = 20
	defaultRetries = 2
	defaultTimeout = 30
)

type sourceDefinition struct {
	id         string
	name       string
	aliases    []string
	fetch      func(string) ([]string, error)
	enabled    func() bool
	enableHint string
}

type sourceResult struct {
	index    int
	source   sourceDefinition
	entries  []string
	err      error
	duration time.Duration
}

var sourceRegistry = []sourceDefinition{
	{id: "crtsh", name: "crt.sh", aliases: []string{"crt.sh", "crtsh"}, fetch: sources.FetchCRTSh},
	{id: "otx", name: "AlienVault OTX", aliases: []string{"otx", "alienvault", "alienvault-otx"}, fetch: sources.FetchOTX},
	{id: "bufferover", name: "BufferOver", aliases: []string{"bufferover", "buffer-over"}, fetch: sources.FetchBufferOver},
	{id: "certspotter", name: "Cert Spotter", aliases: []string{"certspotter", "cert-spotter"}, fetch: sources.FetchCertSpotter},
	{id: "hackertarget", name: "HackerTarget", aliases: []string{"hackertarget", "hacker-target"}, fetch: sources.FetchHackerTarget},
	{id: "anubis", name: "Anubis", aliases: []string{"anubis"}, fetch: sources.FetchAnubis},
	{id: "urlscan", name: "urlscan", aliases: []string{"urlscan", "urlscan.io"}, fetch: sources.FetchURLScan},
	{id: "rapiddns", name: "RapidDNS", aliases: []string{"rapiddns", "rapid-dns"}, fetch: sources.FetchRapidDNS},
	{id: "virustotal", name: "VirusTotal", aliases: []string{"virustotal", "vt"}, fetch: sources.FetchVirusTotal, enabled: sources.VirusTotalEnabled, enableHint: "set VT_API_KEY or add vt_api_key to the config file"},
	{id: "shodan", name: "Shodan", aliases: []string{"shodan"}, fetch: sources.FetchShodan, enabled: sources.ShodanEnabled, enableHint: "set SHODAN_API_KEY or add shodan_api_key to the config file"},
}

func main() {
	configArg, configExplicit, err := discoverConfigPath(os.Args[1:])
	if err != nil {
		fatalError(err)
	}

	configFile, loadedConfigPath, err := config.Load(configArg, configExplicit)
	if err != nil {
		fatalError(fmt.Errorf("failed to load config: %w", err))
	}

	flag.Usage = func() {
		name := filepath.Base(os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s -d example.com [--resolve] [--json|--txt] [--output file] [--source list] [--exclude-source list]\n\n", name)
		fmt.Fprintln(flag.CommandLine.Output(), "Flags:")
		flag.PrintDefaults()
		fmt.Fprintln(flag.CommandLine.Output(), "\nExamples:")
		fmt.Fprintf(flag.CommandLine.Output(), "  %s -d example.com\n", name)
		fmt.Fprintf(flag.CommandLine.Output(), "  %s -d example.com --resolve --threads 10\n", name)
		fmt.Fprintf(flag.CommandLine.Output(), "  %s -d example.com --source crtsh,certspotter,urlscan\n", name)
		fmt.Fprintf(flag.CommandLine.Output(), "  %s -d example.com --exclude-source bufferover\n", name)
		fmt.Fprintf(flag.CommandLine.Output(), "  %s -d example.com --json --output results.json\n", name)
		fmt.Fprintf(flag.CommandLine.Output(), "  %s --sources\n", name)
	}

	var (
		domainShort    = flag.String("d", "", "target domain")
		domainLong     = flag.String("domain", "", "target domain")
		resolveFlag    = flag.Bool("resolve", configBool(configFile.Defaults.Resolve, false), "resolve discovered subdomains")
		jsonFlag       = flag.Bool("json", configBool(configFile.Defaults.JSON, false), "export results as JSON")
		txtFlag        = flag.Bool("txt", configBool(configFile.Defaults.TXT, false), "export results as TXT")
		outputPath     = flag.String("output", configFile.Defaults.Output, "write results to a file")
		sourcesFlag    = flag.Bool("sources", false, "print passive sources used")
		includeSources = flag.String("source", strings.Join(configFile.Defaults.IncludeSources, ","), "comma-separated sources to include")
		excludeSources = flag.String("exclude-source", strings.Join(configFile.Defaults.ExcludeSources, ","), "comma-separated sources to exclude")
		threadsFlag    = flag.Int("threads", configInt(configFile.Defaults.Threads, defaultThreads), "max concurrent source requests and DNS workers")
		timeoutFlag    = flag.Int("timeout", configInt(configFile.Defaults.TimeoutSeconds, defaultTimeout), "HTTP and DNS timeout in seconds")
		retriesFlag    = flag.Int("retries", configInt(configFile.Defaults.Retries, defaultRetries), "retry count for passive source requests")
		verboseFlag    = flag.Bool("verbose", configBool(configFile.Defaults.Verbose, false), "show verbose runtime details")
		configPathFlag = flag.String("config", configArg, "optional config file path")
	)

	flag.Parse()

	_ = configPathFlag

	domain := pickDomain(*domainShort, *domainLong)
	includeList := parseCSVList(*includeSources)
	excludeList := parseCSVList(*excludeSources)
	timeout := time.Duration(*timeoutFlag) * time.Second

	if *threadsFlag <= 0 {
		usageError(errors.New("--threads must be greater than 0"))
	}

	if *timeoutFlag <= 0 {
		usageError(errors.New("--timeout must be greater than 0"))
	}

	if *retriesFlag < 0 {
		usageError(errors.New("--retries cannot be negative"))
	}

	if *jsonFlag && *txtFlag {
		usageError(errors.New("choose either --json or --txt, not both"))
	}

	sources.Configure(sources.Options{
		Timeout:      timeout,
		Retries:      *retriesFlag,
		Verbose:      *verboseFlag,
		OTXAPIKey:    resolveAPIKey("OTX_API_KEY", configFile.OTXAPIKey),
		VTAPIKey:     resolveAPIKey("VT_API_KEY", configFile.VTAPIKey),
		ShodanAPIKey: resolveAPIKey("SHODAN_API_KEY", configFile.ShodanAPIKey),
	})

	selectedSources, err := selectSources(sourceRegistry, includeList, excludeList)
	if err != nil {
		usageError(err)
	}

	if *verboseFlag {
		if loadedConfigPath != "" {
			fmt.Printf("[v] Loaded config: %s\n", loadedConfigPath)
		}
		fmt.Printf("[v] Threads=%d Timeout=%s Retries=%d\n", *threadsFlag, timeout, *retriesFlag)
	}

	if *sourcesFlag {
		printSources(sourceRegistry, selectedSources)
		if domain == "" {
			return
		}
	}

	if domain == "" {
		usageError(errors.New("a target domain is required"))
	}

	domain = normalizeTargetDomain(domain)
	if !isValidDomain(domain) {
		usageError(fmt.Errorf("invalid domain %q", domain))
	}

	format, path, err := determineOutput(*jsonFlag, *txtFlag, *outputPath, domain)
	if err != nil {
		usageError(err)
	}

	runStartedAt := time.Now().UTC()

	fmt.Printf("[+] Target: %s\n", domain)

	sourceResults, hadSuccess := querySources(domain, selectedSources, *threadsFlag, *verboseFlag)
	if !hadSuccess {
		fmt.Fprintln(os.Stderr, "[!] All passive sources failed. No results were collected.")
		os.Exit(1)
	}

	rawResults, unique, attribution := aggregateSourceEntries(domain, sourceResults)
	fmt.Printf("[+] Raw results: %d\n", rawResults)

	fmt.Printf("[+] Unique subdomains: %d\n", len(unique))

	finalResults := unique
	resolveResult := resolver.Result{}
	if *resolveFlag {
		fmt.Println("[+] Resolving discovered hosts...")
		resolveResult = resolver.ResolveSubdomains(unique, resolver.Options{
			Workers:       *threadsFlag,
			LookupTimeout: timeout,
			TargetDomain:  domain,
		})
		finalResults = resolveResult.Live
		if resolveResult.WildcardFiltered > 0 {
			fmt.Printf("[+] Wildcard-filtered subdomains: %d\n", resolveResult.WildcardFiltered)
		}
		fmt.Printf("[+] Live subdomains: %d\n", len(finalResults))
	}

	completedAt := time.Now().UTC()
	reportSubdomains := buildReportSubdomains(finalResults, attribution, resolveResult.Details)
	runMetadata := buildRunMetadata(selectedSources, sourceResults, runStartedAt, completedAt, rawResults, len(unique), len(finalResults), resolveResult.WildcardFiltered)

	if path != "" {
		switch format {
		case "json":
			report := output.Report{
				Domain:          domain,
				Timestamp:       completedAt,
				TotalFound:      len(reportSubdomains),
				ResolvedEnabled: *resolveFlag,
				Metadata:        runMetadata,
				Subdomains:      reportSubdomains,
			}
			err = output.WriteJSON(path, report)
		case "txt":
			err = output.WriteTXT(path, finalResults)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to write output: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("[+] Results written to %s\n", path)
	}

	printSubdomains(finalResults)
}

func querySources(domain string, sourceList []sourceDefinition, threads int, verbose bool) ([]sourceResult, bool) {
	results := make(chan sourceResult, len(sourceList))
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for index, source := range sourceList {
		fmt.Printf("[+] Querying %s...\n", source.name)
		wg.Add(1)

		go func(index int, source sourceDefinition) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			startedAt := time.Now()
			entries, err := source.fetch(domain)
			results <- sourceResult{index: index, source: source, entries: entries, err: err, duration: time.Since(startedAt)}
		}(index, source)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	completedResults := make([]sourceResult, 0, len(sourceList))
	hadSuccess := false

	for result := range results {
		completedResults = append(completedResults, result)

		if result.err != nil {
			health := sources.ErrorHealth(result.err)
			message := sources.ErrorMessage(result.err)
			if verbose {
				fmt.Printf("[!] %s [%s] after %s: %s\n", result.source.name, health, formatDuration(result.duration), message)
			} else {
				fmt.Printf("[!] %s [%s]: %s\n", result.source.name, health, message)
			}
			continue
		}

		hadSuccess = true
		if verbose {
			fmt.Printf("[+] %s returned %d candidate(s) in %s\n", result.source.name, len(result.entries), formatDuration(result.duration))
		} else {
			fmt.Printf("[+] %s returned %d candidate(s)\n", result.source.name, len(result.entries))
		}
	}

	sort.Slice(completedResults, func(i int, j int) bool {
		return completedResults[i].index < completedResults[j].index
	})

	return completedResults, hadSuccess
}

func aggregateSourceEntries(domain string, sourceResults []sourceResult) (int, []string, map[string][]string) {
	rawResults := 0
	attributionSets := make(map[string]map[string]struct{})

	for _, result := range sourceResults {
		if result.err != nil {
			continue
		}

		rawResults += len(result.entries)
		cleaned := utils.Deduplicate(utils.FilterSubdomains(utils.NormalizeEntries(result.entries), domain))
		for _, entry := range cleaned {
			if _, ok := attributionSets[entry]; !ok {
				attributionSets[entry] = make(map[string]struct{})
			}

			attributionSets[entry][result.source.name] = struct{}{}
		}
	}

	unique := make([]string, 0, len(attributionSets))
	attribution := make(map[string][]string, len(attributionSets))
	for subdomain, sourceSet := range attributionSets {
		unique = append(unique, subdomain)

		sourcesForSubdomain := make([]string, 0, len(sourceSet))
		for sourceName := range sourceSet {
			sourcesForSubdomain = append(sourcesForSubdomain, sourceName)
		}

		sort.Strings(sourcesForSubdomain)
		attribution[subdomain] = sourcesForSubdomain
	}

	sort.Strings(unique)
	return rawResults, unique, attribution
}

func buildReportSubdomains(subdomains []string, attribution map[string][]string, details map[string]resolver.Resolution) []output.Subdomain {
	reportSubdomains := make([]output.Subdomain, 0, len(subdomains))
	for _, subdomain := range subdomains {
		entry := output.Subdomain{
			Name:    subdomain,
			Sources: attribution[subdomain],
		}

		if detail, ok := details[subdomain]; ok {
			entry.IPs = detail.IPs
			entry.CNAMEs = detail.CNAMEs
		}

		reportSubdomains = append(reportSubdomains, entry)
	}

	return reportSubdomains
}

func buildRunMetadata(selectedSources []sourceDefinition, sourceResults []sourceResult, startedAt time.Time, completedAt time.Time, rawResults int, uniqueCount int, finalCount int, wildcardFiltered int) output.RunMetadata {
	enabledSources := make([]output.SourceReference, 0, len(selectedSources))
	for _, source := range selectedSources {
		enabledSources = append(enabledSources, output.SourceReference{ID: source.id, Name: source.name})
	}

	failedSources := make([]output.FailedSource, 0)
	timings := make([]output.SourceTiming, 0, len(sourceResults))
	for _, result := range sourceResults {
		status := "success"
		if result.err != nil {
			status = string(sources.ErrorHealth(result.err))
			failedSources = append(failedSources, output.FailedSource{
				ID:         result.source.id,
				Name:       result.source.name,
				Health:     status,
				Error:      sources.ErrorMessage(result.err),
				DurationMS: result.duration.Milliseconds(),
			})
		}

		timings = append(timings, output.SourceTiming{
			ID:         result.source.id,
			Name:       result.source.name,
			Status:     status,
			Candidates: len(result.entries),
			DurationMS: result.duration.Milliseconds(),
		})
	}

	return output.RunMetadata{
		StartedAt:        startedAt,
		CompletedAt:      completedAt,
		DurationMS:       completedAt.Sub(startedAt).Milliseconds(),
		RawResults:       rawResults,
		UniqueSubdomains: uniqueCount,
		FinalSubdomains:  finalCount,
		WildcardFiltered: wildcardFiltered,
		EnabledSources:   enabledSources,
		FailedSources:    failedSources,
		SourceTimings:    timings,
	}
}

func selectSources(registry []sourceDefinition, include []string, exclude []string) ([]sourceDefinition, error) {
	aliasMap := buildSourceAliasMap(registry)

	selected := make([]sourceDefinition, 0, len(registry))
	selectedIDs := make(map[string]struct{}, len(registry))

	if len(include) == 0 {
		for _, source := range registry {
			if sourceIsEnabled(source) {
				selected = append(selected, source)
				selectedIDs[source.id] = struct{}{}
			}
		}
	} else {
		for _, name := range include {
			source, ok := aliasMap[name]
			if !ok {
				return nil, fmt.Errorf("unknown source %q", name)
			}

			if !sourceIsEnabled(source) {
				return nil, fmt.Errorf("source %q is not available: %s", source.name, source.enableHint)
			}

			if _, ok := selectedIDs[source.id]; ok {
				continue
			}

			selected = append(selected, source)
			selectedIDs[source.id] = struct{}{}
		}
	}

	if len(exclude) == 0 {
		if len(selected) == 0 {
			return nil, errors.New("no sources are enabled")
		}

		return selected, nil
	}

	excludedIDs := make(map[string]struct{}, len(exclude))
	for _, name := range exclude {
		source, ok := aliasMap[name]
		if !ok {
			return nil, fmt.Errorf("unknown source %q", name)
		}

		excludedIDs[source.id] = struct{}{}
	}

	filtered := make([]sourceDefinition, 0, len(selected))
	for _, source := range selected {
		if _, ok := excludedIDs[source.id]; ok {
			continue
		}

		filtered = append(filtered, source)
	}

	if len(filtered) == 0 {
		return nil, errors.New("no sources selected after applying include/exclude filters")
	}

	return filtered, nil
}

func printSources(registry []sourceDefinition, selected []sourceDefinition) {
	fmt.Println("[+] Selected passive sources:")
	for _, source := range selected {
		fmt.Printf("    - %s (%s) [%s]\n", source.name, source.id, sourceAvailability(source))
	}

	disabled := disabledOptionalSources(registry)
	if len(disabled) == 0 {
		return
	}

	fmt.Println("[+] Optional passive sources not enabled:")
	for _, source := range disabled {
		fmt.Printf("    - %s (%s) [%s] - %s\n", source.name, source.id, sources.HealthDisabled, source.enableHint)
	}
}

func sourceAvailability(source sourceDefinition) sources.Health {
	if sourceIsEnabled(source) {
		return sources.HealthEnabled
	}

	return sources.HealthDisabled
}

func disabledOptionalSources(registry []sourceDefinition) []sourceDefinition {
	disabled := make([]sourceDefinition, 0)
	for _, source := range registry {
		if source.enabled == nil || source.enabled() {
			continue
		}

		disabled = append(disabled, source)
	}

	return disabled
}

func sourceIsEnabled(source sourceDefinition) bool {
	if source.enabled == nil {
		return true
	}

	return source.enabled()
}

func buildSourceAliasMap(registry []sourceDefinition) map[string]sourceDefinition {
	aliasMap := make(map[string]sourceDefinition, len(registry)*3)
	for _, source := range registry {
		aliasMap[source.id] = source
		for _, alias := range source.aliases {
			aliasMap[alias] = source
		}
	}

	return aliasMap
}

func parseCSVList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	parts := strings.Split(value, ",")
	list := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))

	for _, part := range parts {
		name := strings.ToLower(strings.TrimSpace(part))
		if name == "" {
			continue
		}

		if _, ok := seen[name]; ok {
			continue
		}

		seen[name] = struct{}{}
		list = append(list, name)
	}

	return list
}

func discoverConfigPath(args []string) (string, bool, error) {
	for index := 0; index < len(args); index++ {
		argument := args[index]

		switch {
		case argument == "--config" || argument == "-config":
			if index+1 >= len(args) {
				return "", true, errors.New("--config requires a path")
			}
			return args[index+1], true, nil
		case strings.HasPrefix(argument, "--config="):
			return strings.TrimPrefix(argument, "--config="), true, nil
		case strings.HasPrefix(argument, "-config="):
			return strings.TrimPrefix(argument, "-config="), true, nil
		}
	}

	return "", false, nil
}

func pickDomain(short string, long string) string {
	if strings.TrimSpace(short) != "" {
		return short
	}

	return long
}

func normalizeTargetDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimSuffix(domain, ".")
	return domain
}

func isValidDomain(domain string) bool {
	if domain == "" || strings.Contains(domain, "..") || strings.ContainsAny(domain, "/:@ ") {
		return false
	}

	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}

	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}

		for _, char := range label {
			isLetter := char >= 'a' && char <= 'z'
			isDigit := char >= '0' && char <= '9'
			if !isLetter && !isDigit && char != '-' {
				return false
			}
		}
	}

	return true
}

func determineOutput(jsonFlag bool, txtFlag bool, outputPath string, domain string) (string, string, error) {
	if outputPath == "" && !jsonFlag && !txtFlag {
		return "", "", nil
	}

	format := ""
	switch {
	case jsonFlag:
		format = "json"
	case txtFlag:
		format = "txt"
	default:
		switch strings.ToLower(filepath.Ext(outputPath)) {
		case ".json":
			format = "json"
		case ".txt":
			format = "txt"
		default:
			return "", "", errors.New("use --json or --txt when --output does not end in .json or .txt")
		}
	}

	if outputPath == "" {
		outputPath = fmt.Sprintf("subscan-%s.%s", domain, format)
	}

	return format, outputPath, nil
}

func printSubdomains(subdomains []string) {
	if len(subdomains) == 0 {
		fmt.Println("[+] No matching subdomains found.")
		return
	}

	fmt.Println()
	for _, subdomain := range subdomains {
		fmt.Println(subdomain)
	}
}

func configBool(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}

	return *value
}

func configInt(value *int, fallback int) int {
	if value == nil {
		return fallback
	}

	return *value
}

func resolveAPIKey(envName string, configValue string) string {
	if envValue := strings.TrimSpace(os.Getenv(envName)); envValue != "" {
		return envValue
	}

	return strings.TrimSpace(configValue)
}

func formatDuration(duration time.Duration) string {
	if duration < time.Second {
		return duration.Round(10 * time.Millisecond).String()
	}

	return duration.Round(100 * time.Millisecond).String()
}

func usageError(err error) {
	fmt.Fprintf(os.Stderr, "[!] %v\n\n", err)
	flag.Usage()
	os.Exit(1)
}

func fatalError(err error) {
	fmt.Fprintf(os.Stderr, "[!] %v\n", err)
	os.Exit(1)
}
