/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/tbot/bot"
	"github.com/gravitational/teleport/lib/tbot/botfs"
	"github.com/gravitational/teleport/lib/utils/golden"
)

func TestConfigCLIOnlySample(t *testing.T) {
	// Test the sample config generated by `tctl bots add ...`
	cf := CLIConf{
		DestinationDir: "/tmp/foo",
		Token:          "foo",
		CAPins:         []string{"abc123"},
		AuthServer:     "auth.example.com",
		DiagAddr:       "127.0.0.1:1337",
		Debug:          true,
		JoinMethod:     string(types.JoinMethodToken),
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
	storageImpl, ok := cfg.Storage.Destination.(*DestinationDirectory)
	require.True(t, ok)
	require.Equal(t, defaultStoragePath, storageImpl.Path)

	// A single default Destination should exist
	require.Len(t, cfg.Outputs, 1)
	output := cfg.Outputs[0]

	destImpl := output.GetDestination()
	require.NoError(t, err)
	destImplReal, ok := destImpl.(*DestinationDirectory)
	require.True(t, ok)

	require.Equal(t, cf.DestinationDir, destImplReal.Path)
	require.Equal(t, cf.Debug, cfg.Debug)
	require.Equal(t, cf.DiagAddr, cfg.DiagAddr)
}

func TestConfigFile(t *testing.T) {
	configData := fmt.Sprintf(exampleConfigFile, "foo")
	cfg, err := ReadConfig(strings.NewReader(configData), false)
	require.NoError(t, err)

	require.Equal(t, "auth.example.com", cfg.AuthServer)
	require.Equal(t, time.Minute*5, cfg.RenewalInterval)

	require.NotNil(t, cfg.Onboarding)

	token, err := cfg.Onboarding.Token()
	require.NoError(t, err)
	require.Equal(t, "foo", token)
	require.ElementsMatch(t, []string{"sha256:abc123"}, cfg.Onboarding.CAPins)

	_, ok := cfg.Storage.Destination.(*DestinationMemory)
	require.True(t, ok)

	require.Len(t, cfg.Outputs, 1)
	output := cfg.Outputs[0]
	_, ok = output.(*IdentityOutput)
	require.True(t, ok)

	destImpl := output.GetDestination()
	destImplReal, ok := destImpl.(*DestinationDirectory)
	require.True(t, ok)
	require.Equal(t, "/tmp/foo", destImplReal.Path)

	require.True(t, cfg.Debug)
	require.Equal(t, "127.0.0.1:1337", cfg.DiagAddr)
}

func TestLoadTokenFromFile(t *testing.T) {
	tokenDir := t.TempDir()
	tokenFile := filepath.Join(tokenDir, "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("xxxyyy"), 0660))

	configData := fmt.Sprintf(exampleConfigFile, tokenFile)
	cfg, err := ReadConfig(strings.NewReader(configData), false)
	require.NoError(t, err)

	token, err := cfg.Onboarding.Token()
	require.NoError(t, err)
	require.Equal(t, "xxxyyy", token)
}

const exampleConfigFile = `
version: v2
auth_server: auth.example.com
renewal_interval: 5m
debug: true
diag_addr: 127.0.0.1:1337
onboarding:
  token: %s
  ca_pins:
    - sha256:abc123
storage:
  type: memory
outputs:
  - type: identity
    destination:
      type: directory
      path: /tmp/foo
`

func TestDestinationFromURI(t *testing.T) {
	tests := []struct {
		in      string
		want    bot.Destination
		wantErr bool
	}{
		{
			in: "/absolute/dir",
			want: &DestinationDirectory{
				Path: "/absolute/dir",
			},
		},
		{
			in: "relative/dir",
			want: &DestinationDirectory{
				Path: "relative/dir",
			},
		},
		{
			in: "./relative/dir",
			want: &DestinationDirectory{
				Path: "./relative/dir",
			},
		},
		{
			in: "file:///absolute/dir",
			want: &DestinationDirectory{
				Path: "/absolute/dir",
			},
		},
		{
			in: "file:/absolute/dir",
			want: &DestinationDirectory{
				Path: "/absolute/dir",
			},
		},
		{
			in:      "file://host/absolute/dir",
			wantErr: true,
		},
		{
			in:   "memory://",
			want: &DestinationMemory{},
		},
		{
			in:      "memory://foo/bar",
			wantErr: true,
		},
		{
			in:      "foobar://",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := destinationFromURI(tt.in)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// TestBotConfig_YAML ensures that as a whole YAML marshaling and unmarshaling
// of the config works as expected. Avoid testing exhaustive cases here and
// prefer the Output YAML tests for testing the intricacies of marshaling and
// unmarshaling specific objects.
func TestBotConfig_YAML(t *testing.T) {
	tests := []testYAMLCase[BotConfig]{
		{
			name: "standard config",
			in: BotConfig{
				Version: V2,
				Storage: &StorageConfig{
					Destination: &DestinationDirectory{
						Path:     "/bot/storage",
						ACLs:     botfs.ACLTry,
						Symlinks: botfs.SymlinksSecure,
					},
				},
				FIPS:            true,
				Debug:           true,
				Oneshot:         true,
				AuthServer:      "example.teleport.sh:443",
				DiagAddr:        "127.0.0.1:1337",
				CertificateTTL:  time.Minute,
				RenewalInterval: time.Second * 30,
				Outputs: Outputs{
					&IdentityOutput{
						Destination: &DestinationDirectory{
							Path: "/bot/output",
						},
						Roles:   []string{"editor"},
						Cluster: "example.teleport.sh",
					},
					&IdentityOutput{
						Destination: &DestinationMemory{},
					},
					&IdentityOutput{
						Destination: &DestinationKubernetesSecret{
							Name: "my-secret",
						},
					},
				},
				Services: []ServiceConfig{
					&SPIFFEWorkloadAPIService{
						Listen: "unix:///var/run/spiffe.sock",
						SVIDs: []SVIDRequest{
							{
								Path: "/bar",
								Hint: "my hint",
								SANS: SVIDRequestSANs{
									DNS: []string{"foo.bar"},
									IP:  []string{"10.0.0.1"},
								},
							},
						},
					},
					&ExampleService{
						Message: "llama",
					},
				},
			},
		},
		{
			name: "minimal config",
			in: BotConfig{
				Version:         V2,
				AuthServer:      "example.teleport.sh:443",
				CertificateTTL:  time.Minute,
				RenewalInterval: time.Second * 30,
				Outputs: Outputs{
					&IdentityOutput{
						Destination: &DestinationMemory{},
					},
				},
			},
		},
		{
			name: "minimal config using proxy addr",
			in: BotConfig{
				Version:         V2,
				ProxyServer:     "example.teleport.sh:443",
				CertificateTTL:  time.Minute,
				RenewalInterval: time.Second * 30,
				Outputs: Outputs{
					&IdentityOutput{
						Destination: &DestinationMemory{},
					},
				},
			},
		},
	}

	testYAML(t, tests)
}

type testYAMLCase[T any] struct {
	name string
	in   T
}

func testYAML[T any](t *testing.T, tests []testYAMLCase[T]) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := bytes.NewBuffer(nil)
			encoder := yaml.NewEncoder(b)
			encoder.SetIndent(2)
			require.NoError(t, encoder.Encode(&tt.in))

			if golden.ShouldSet() {
				golden.Set(t, b.Bytes())
			}
			require.Equal(
				t,
				string(golden.Get(t)),
				b.String(),
				"results of marshal did not match golden file, rerun tests with GOLDEN_UPDATE=1",
			)

			// Now test unmarshalling to see if we get the same object back
			decoder := yaml.NewDecoder(b)
			var unmarshalled T
			require.NoError(t, decoder.Decode(&unmarshalled))
			require.Equal(t, unmarshalled, tt.in, "unmarshalling did not result in same object as input")
		})
	}
}

func TestBotConfig_InsecureWithCAPins(t *testing.T) {
	cfg := &BotConfig{
		Insecure: true,
		Onboarding: OnboardingConfig{
			CAPins: []string{"123"},
		},
	}

	require.ErrorContains(t, cfg.CheckAndSetDefaults(), "ca-pin")
}

func TestBotConfig_InsecureWithCAPath(t *testing.T) {
	cfg := &BotConfig{
		Insecure: true,
		Onboarding: OnboardingConfig{
			CAPath: "/tmp/invalid-path/some.crt",
		},
	}

	require.ErrorContains(t, cfg.CheckAndSetDefaults(), "ca-path")
}

func TestBotConfig_WithCAPathAndCAPins(t *testing.T) {
	cfg := &BotConfig{
		Insecure: false,
		Onboarding: OnboardingConfig{
			CAPath: "/tmp/invalid-path/some.crt",
			CAPins: []string{"123"},
		},
	}

	require.ErrorContains(t, cfg.CheckAndSetDefaults(), "mutually exclusive")
}
