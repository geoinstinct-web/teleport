/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-semver/semver"
	"github.com/stretchr/testify/require"
)

func TestConfigDefaults(t *testing.T) {
	cfg, err := NewDefaultConfig("auth.example.com")
	require.NoError(t, err)

	require.Equal(t, DefaultCertificateTTL, cfg.CertificateTTL)
	require.Equal(t, DefaultRenewInterval, cfg.RenewalInterval)

	storageDest, err := cfg.Storage.GetDestination()
	require.NoError(t, err)

	storageImpl, ok := storageDest.(*DestinationDirectory)
	require.True(t, ok)

	require.Equal(t, defaultStoragePath, storageImpl.Path)

	// Onboarding config unset
	require.Nil(t, cfg.Onboarding)

	// Default config has no destinations (without CLI)
	require.Empty(t, cfg.Destinations)
}

func TestConfigCLIOnlySample(t *testing.T) {
	// Test the sample config generated by `tctl bots add ...`
	cf := CLIConf{
		DestinationDir: "/tmp/foo",
		Token:          "foo",
		CAPins:         []string{"abc123"},
		AuthServer:     "auth.example.com",
	}
	cfg, err := FromCLIConf(&cf)
	require.NoError(t, err)

	require.Equal(t, cf.AuthServer, cfg.AuthServer)

	require.NotNil(t, cfg.Onboarding)

	token, err := cfg.Onboarding.Token()
	require.NoError(t, err)
	require.Equal(t, cf.Token, token)
	require.Equal(t, cf.CAPins, cfg.Onboarding.CAPins)

	// Storage is still default
	storageDest, err := cfg.Storage.GetDestination()
	require.NoError(t, err)
	storageImpl, ok := storageDest.(*DestinationDirectory)
	require.True(t, ok)
	require.Equal(t, defaultStoragePath, storageImpl.Path)

	// A single default destination should exist
	require.Len(t, cfg.Destinations, 1)
	dest := cfg.Destinations[0]

	// We have 3 required/default templates.
	require.Len(t, dest.Configs, 3)
	template := dest.Configs[0]
	require.NotNil(t, template.SSHClient)

	destImpl, err := dest.GetDestination()
	require.NoError(t, err)
	destImplReal, ok := destImpl.(*DestinationDirectory)
	require.True(t, ok)

	require.Equal(t, cf.DestinationDir, destImplReal.Path)
}

func TestConfigFile(t *testing.T) {
	configData := fmt.Sprintf(exampleConfigFile, "foo")
	cfg, err := ReadConfig(strings.NewReader(configData))
	require.NoError(t, err)

	require.Equal(t, "auth.example.com", cfg.AuthServer)
	require.Equal(t, time.Minute*5, cfg.RenewalInterval)

	require.NotNil(t, cfg.Onboarding)

	token, err := cfg.Onboarding.Token()
	require.NoError(t, err)
	require.Equal(t, "foo", token)
	require.ElementsMatch(t, []string{"sha256:abc123"}, cfg.Onboarding.CAPins)

	storage, err := cfg.Storage.GetDestination()
	require.NoError(t, err)

	_, ok := storage.(*DestinationMemory)
	require.True(t, ok)

	require.Len(t, cfg.Destinations, 1)
	destination := cfg.Destinations[0]

	require.Len(t, destination.Configs, 1)
	template := destination.Configs[0]
	templateImpl, err := template.GetConfigTemplate()
	require.NoError(t, err)
	sshTemplate, ok := templateImpl.(*TemplateSSHClient)
	require.True(t, ok)
	require.Equal(t, uint16(1234), sshTemplate.ProxyPort)

	destImpl, err := destination.GetDestination()
	require.NoError(t, err)
	destImplReal, ok := destImpl.(*DestinationDirectory)
	require.True(t, ok)
	require.Equal(t, "/tmp/foo", destImplReal.Path)
}

func TestLoadTokenFromFile(t *testing.T) {
	tokenDir := t.TempDir()
	tokenFile := filepath.Join(tokenDir, "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("xxxyyy"), 0660))

	configData := fmt.Sprintf(exampleConfigFile, tokenFile)
	cfg, err := ReadConfig(strings.NewReader(configData))
	require.NoError(t, err)

	token, err := cfg.Onboarding.Token()
	require.NoError(t, err)
	require.Equal(t, token, "xxxyyy")
}

func TestParseSSHVersion(t *testing.T) {
	tests := []struct {
		str     string
		version *semver.Version
		err     bool
	}{
		{
			str:     "OpenSSH_8.2p1 Ubuntu-4ubuntu0.4, OpenSSL 1.1.1f  31 Mar 2020",
			version: semver.New("8.2.1"),
		},
		{
			str:     "OpenSSH_8.8p1, OpenSSL 1.1.1m  14 Dec 2021",
			version: semver.New("8.8.1"),
		},
		{
			str:     "OpenSSH_7.5p1, OpenSSL 1.0.2s-freebsd  28 May 2019",
			version: semver.New("7.5.1"),
		},
		{
			str:     "OpenSSH_7.9p1 Raspbian-10+deb10u2, OpenSSL 1.1.1d  10 Sep 2019",
			version: semver.New("7.9.1"),
		},
		{
			// Couldn't find a full example but in theory patch is optional:
			str:     "OpenSSH_8.1 foo",
			version: semver.New("8.1.0"),
		},
		{
			str: "Teleport v8.0.0-dev.40 git:v8.0.0-dev.40-0-ge9194c256 go1.17.2",
			err: true,
		},
	}

	for _, test := range tests {
		version, err := parseSSHVersion(test.str)
		if test.err {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			require.True(t, version.Equal(*test.version), "got version = %v, want = %v", version, test.version)
		}
	}
}

const exampleConfigFile = `
auth_server: auth.example.com
renewal_interval: 5m
onboarding:
  token: %s
  ca_pins:
    - sha256:abc123
storage:
  memory: {}
destinations:
  - directory:
      path: /tmp/foo
    configs:
      - ssh_client:
          proxy_port: 1234
`
