/*
Copyright 2021 Gravitational, Inc.

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

package keystore

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func HSMTestConfig(t *testing.T) Config {
	if cfg, ok := yubiHSMTestConfig(t); ok {
		t.Log("Running test with YubiHSM")
		return cfg
	}
	if cfg, ok := cloudHSMTestConfig(t); ok {
		t.Log("Running test with AWS CloudHSM")
		return cfg
	}
	if cfg, ok := gcpKMSTestConfig(t); ok {
		t.Log("Running test with GCP KMS")
		return cfg
	}
	if cfg, ok := softHSMTestConfig(t); ok {
		t.Log("Running test with SoftHSM")
		return cfg
	}
	t.Skip("No HSM available for test")
	return Config{}
}

func yubiHSMTestConfig(t *testing.T) (Config, bool) {
	yubiHSMPath := os.Getenv("TELEPORT_TEST_YUBIHSM_PKCS11_PATH")
	yubiHSMPin := os.Getenv("TELEPORT_TEST_YUBIHSM_PIN")
	if yubiHSMPath == "" || yubiHSMPin == "" {
		return Config{}, false
	}
	slotNumber := 0
	return Config{
		PKCS11: PKCS11Config{
			Path:       yubiHSMPath,
			SlotNumber: &slotNumber,
			Pin:        yubiHSMPin,
		},
	}, true
}

func cloudHSMTestConfig(t *testing.T) (Config, bool) {
	cloudHSMPin := os.Getenv("TELEPORT_TEST_CLOUDHSM_PIN")
	if cloudHSMPin == "" {
		return Config{}, false
	}
	return Config{
		PKCS11: PKCS11Config{
			Path:       "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
			TokenLabel: "cavium",
			Pin:        cloudHSMPin,
		},
	}, true
}

func gcpKMSTestConfig(t *testing.T) (Config, bool) {
	gcpKeyring := os.Getenv("TELEPORT_TEST_GCP_KMS_KEYRING")
	if gcpKeyring == "" {
		return Config{}, false
	}
	return Config{
		GCPKMS: GCPKMSConfig{
			KeyRing:         gcpKeyring,
			ProtectionLevel: "SOFTWARE",
		},
	}, true
}

var (
	cachedSoftHSMConfig      *Config
	cachedSoftHSMConfigMutex sync.Mutex
)

// softHSMTestConfig is for use in tests only and creates a test SOFTHSM2 token.
// This should be used for all tests which need to use SoftHSM because the
// library can only be initialized once and SOFTHSM2_PATH and SOFTHSM2_CONF
// cannot be changed. New tokens added after the library has been initialized
// will not be found by the library.
//
// A new token will be used for each `go test` invocation, but it's difficult
// to create a separate token for each test because because new tokens
// added after the library has been initialized will not be found by the
// library. It's also difficult to clean up the token because tests for all
// packages are run in parallel there is not a good time to safely
// delete the token or the entire token directory. Each test should clean up
// all keys that it creates because SoftHSM2 gets really slow when there are
// many keys for a given token.
func softHSMTestConfig(t *testing.T) (Config, bool) {
	path := os.Getenv("SOFTHSM2_PATH")
	if path == "" {
		return Config{}, false
	}

	cachedSoftHSMConfigMutex.Lock()
	defer cachedSoftHSMConfigMutex.Unlock()

	if cachedSoftHSMConfig != nil {
		return *cachedSoftHSMConfig, true
	}

	if os.Getenv("SOFTHSM2_CONF") == "" {
		// create tokendir
		tokenDir, err := os.MkdirTemp("", "tokens")
		require.NoError(t, err)

		// create config file
		configFile, err := os.CreateTemp("", "softhsm2.conf")
		require.NoError(t, err)

		// write config file
		_, err = configFile.WriteString(fmt.Sprintf(
			"directories.tokendir = %s\nobjectstore.backend = file\nlog.level = DEBUG\n",
			tokenDir))
		require.NoError(t, err)
		require.NoError(t, configFile.Close())

		// set env
		os.Setenv("SOFTHSM2_CONF", configFile.Name())
	}

	// create test token (max length is 32 chars)
	tokenLabel := strings.Replace(uuid.NewString(), "-", "", -1)
	cmd := exec.Command("softhsm2-util", "--init-token", "--free", "--label", tokenLabel, "--so-pin", "password", "--pin", "password")
	t.Logf("Running command: %q", cmd)
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			require.NoError(t, exitErr, "error creating test softhsm token: %s", string(exitErr.Stderr))
		}
		require.NoError(t, err, "error attempting to run softhsm2-util")
	}

	cachedSoftHSMConfig = &Config{
		PKCS11: PKCS11Config{
			Path:       path,
			TokenLabel: tokenLabel,
			Pin:        "password",
		},
	}
	return *cachedSoftHSMConfig, true
}
