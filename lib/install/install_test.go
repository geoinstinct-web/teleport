/*
 * Teleport
 * Copyright (C) 2024  Gravitational, Inc.
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

package install

import (
	"context"
	"io/fs"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInstallLocal(t *testing.T) {
	ctx := context.Background()
	baseConfig := &InstallTeleportConfig{
		RepositoryChannel: "x",
		Version:           "15.3.2",
		Enterprise:        false,
		AutoUpgrades:      false,
	}

	for _, tt := range []struct {
		name       string
		distroName string
		config     *InstallTeleportConfig
	}{
		{
			name:       "ubuntu 24.04 lts",
			distroName: "ubuntu:24.04",
		},
		{
			name:       "ubuntu 22.04 lts",
			distroName: "ubuntu:22.04",
		},
		{
			name:       "ubuntu 20.04 lts",
			distroName: "ubuntu:20.04",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			testTempDir := t.TempDir()
			testConfig := baseConfig
			testConfig.FSRootPrefix = testTempDir

			setupWellKnownDistroInitialFS(t, tt.distroName, testTempDir)

			teleportInstaller, err := NewInstaller(testConfig)
			require.NoError(t, err)

			require.NoError(t, teleportInstaller.Install(ctx))
		})
	}
}

func setupWellKnownDistroInitialFS(t *testing.T, distroName string, rootPrefix string) {
	t.Helper()

	// Set up default and common dirs.
	for _, dir := range []string{"/etc"} {
		require.NoError(t, os.Mkdir(rootPrefix+dir, fs.ModePerm))
	}

	distroInitialFS, ok := wellKnownOSInitialFS[distroName]
	if !ok {
		t.Log("distro not supported", distroName)
		t.FailNow()
	}

	for filePath, fileContents := range distroInitialFS {
		require.NoError(t, os.WriteFile(rootPrefix+filePath, []byte(fileContents), fs.ModePerm))
	}
}

var wellKnownOSInitialFS = map[string]map[string]string{
	"ubuntu:24.04": {
		// docker run ubuntu:24.04 cat /etc/os-release
		"/etc/os-release": `PRETTY_NAME="Ubuntu 24.04 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=noble
LOGO=ubuntu-logo`,
	},
	"ubuntu:22.04": {
		// docker run ubuntu:22.04 cat /etc/os-release
		"/etc/os-release": `PRETTY_NAME="Ubuntu 22.04 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy`,
	},
	"ubuntu:20.04": {
		// docker run ubuntu:20.04 cat /etc/os-release
		"/etc/os-release": `NAME="Ubuntu"
VERSION="20.04.6 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.6 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal`,
	},
}
