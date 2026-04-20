package buildinfo

import (
	"fmt"
	"runtime"
	"strings"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "local"
)

type Info struct {
	Version  string
	Commit   string
	Date     string
	BuiltBy  string
	Go       string
	Platform string
}

func Current() Info {
	return Info{
		Version:  version,
		Commit:   commit,
		Date:     date,
		BuiltBy:  builtBy,
		Go:       runtime.Version(),
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
	}
}

func (info Info) String() string {
	parts := []string{
		fmt.Sprintf("subscan %s", info.Version),
		fmt.Sprintf("commit=%s", info.Commit),
		fmt.Sprintf("built=%s", info.Date),
		fmt.Sprintf("builder=%s", info.BuiltBy),
		fmt.Sprintf("go=%s", info.Go),
		fmt.Sprintf("platform=%s", info.Platform),
	}

	return strings.Join(parts, " ")
}
