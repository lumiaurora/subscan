# Contributing

Thanks for contributing to `subscan`.

## Ground rules

- Keep the project passive-only. Do not add brute force, active scanning, HTTP probing, port scanning, screenshots, takeover detection, or other aggressive behavior without an explicit scope change.
- Prefer small, focused pull requests.
- Favor standard library solutions and simple, readable code over clever abstractions.
- Keep new behavior covered by tests when practical.

## Development setup

Requirements:

- Go `1.22+`
- Git
- Optional: `goreleaser`, `syft`, and `cosign` for release work

Clone and build:

```bash
git clone https://github.com/lumiaurora/subscan.git
cd subscan
go build ./...
```

Run locally:

```bash
go run . -d example.com
go run . --version
```

## Test commands

Run these before opening a pull request:

```bash
gofmt -w .
go test ./...
go test -race ./...
go build ./...
```

Optional live integration test:

```bash
SUBSCAN_RUN_LIVE_TESTS=1 SUBSCAN_LIVE_DOMAIN=cloudflare.com go test -tags=integration ./...
```

## Project conventions

- Keep functions small and readable.
- Add comments only when they help explain non-obvious logic.
- Preserve the existing CLI tone and output style.
- Prefer adding or refining parser fixtures when changing source integrations.
- Do not silently weaken filtering or passive-only guardrails.

## Pull requests

Please include:

- a short description of the problem and the change
- relevant test or verification steps
- sample CLI output when behavior changes
- documentation updates when flags, outputs, or release behavior change

Good pull requests usually do one of these well:

- improve source reliability
- improve output quality or UX
- improve tests and release engineering
- improve docs and maintainability

## Reporting issues

- Use the bug report template for defects and regressions.
- Use the feature request template for enhancements.
- Do not report security issues publicly. Follow `SECURITY.md` instead.

## Release notes

User-visible changes should also update `README.md` or `CHANGELOG.md` when appropriate.
