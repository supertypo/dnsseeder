package checkversion

import (
	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	_ "net/http/pprof"
	"regexp"
	"strings"
)

var versionRegexp = regexp.MustCompile(`\b(\d+\.\d+\.\d+)\b`)

func CheckVersion(minVersion string, userAgent string) error {
	if minVersion == "" {
		return nil
	}
	minVer, err := version.NewVersion(minVersion)
	if err != nil {
		return err
	}
	trimmed := strings.TrimPrefix(userAgent, "/")
	end := strings.Index(trimmed, "/")
	if end == -1 {
		return errors.New("Invalid userAgent format")
	}
	firstGroup := trimmed[:end]
	matches := versionRegexp.FindStringSubmatch(firstGroup)
	if len(matches) < 2 {
		return errors.New("No valid version found in userAgent")
	}
	clientVer, err := version.NewVersion(matches[1])
	if err != nil {
		return err
	}
	if clientVer.LessThan(minVer) {
		return errors.New("UserAgent version is below minimum required")
	}
	return nil
}
