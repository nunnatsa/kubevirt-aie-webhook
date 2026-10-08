package tlssettings

import (
	"crypto/tls"
	"os"
	"strings"

	"github.com/go-logr/logr"
	cliflag "k8s.io/component-base/cli/flag"
)

func AppendCipherSuites(logger logr.Logger, tlsOpts []func(*tls.Config), cipherSuitesFlag string) []func(*tls.Config) {
	if cipherSuitesFlag == "" {
		return tlsOpts
	}
	cipherSuites := strings.Split(cipherSuitesFlag, ",")
	cipherSuiteIDs, err := cliflag.TLSCipherSuites(cipherSuites)
	if err != nil {
		logger.Error(err, "failed to parse TLS cipher suites")
		os.Exit(1)
	}

	setCipherSuites := func(c *tls.Config) {
		logger.Info("setting tls cipher suites to " + strings.Join(cipherSuites, ", "))
		c.CipherSuites = cipherSuiteIDs
	}

	return append(tlsOpts, setCipherSuites)
}

func AppendMinTLSVersion(logger logr.Logger, tlsOpts []func(*tls.Config), minTLSVersion string) []func(*tls.Config) {
	if minTLSVersion == "" {
		return tlsOpts
	}
	minTLSVersionID, err := cliflag.TLSVersion(minTLSVersion)
	if err != nil {
		logger.Error(err, "failed to parse TLS min version")
		os.Exit(1)
	}

	setMinTLSVersion := func(c *tls.Config) {
		logger.Info("setting tls min version to " + minTLSVersion)
		c.MinVersion = minTLSVersionID
	}

	return append(tlsOpts, setMinTLSVersion)
}
