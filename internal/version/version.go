// Package version 集中管理构建版本信息，由 ldflags 注入。
package version

import "fmt"

var (
	Version   = "1.0.0"
	BuildTime = "dev"
	GitRev    = "none"
)

func String() string {
	return fmt.Sprintf("%s (build %s, rev %s)", Version, BuildTime, GitRev)
}
