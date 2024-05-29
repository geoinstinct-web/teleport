// Teleport
// Copyright (C) 2024 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package install

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/utils"
)

type packageManagerAPT struct {
	HTTPClient *http.Client

	// legacy indicates that the old method of adding repos must be used.
	// This is used in Xenial (16.04) and Trusty (14.04) Ubuntu releases.
	legacy bool

	// fsRootPrefix is the prefix to use when reading operating system information and when installing teleport.
	// This is mostly used for testing without intering with
	fsRootPrefix string

	logger *slog.Logger
}

// NewPackageManagerAPT creates a new PackageManagerAPT.
func NewPackageManagerAPT(fsRootPrefix string) *packageManagerAPT {
	return &packageManagerAPT{
		fsRootPrefix: fsRootPrefix,
		HTTPClient:   http.DefaultClient,
		logger:       slog.Default(),
	}
}

// NewPackageManagerAPTLegacy creates a new PackageManagerAPT for legacy ubuntu versions (Xenial and Trusty).
func NewPackageManagerAPTLegacy(fsRootPrefix string) *packageManagerAPT {
	pm := NewPackageManagerAPT(fsRootPrefix)
	pm.legacy = true
	pm.logger = pm.logger.With("legacy", "true")
	return pm
}

const (
	aptPublicKeyEndpoint = "https://apt.releases.teleport.dev/gpg"
	aptRepoEndpoint      = "https://apt.releases.teleport.dev/"

	aptTeleportSourceListFileRelative = "/etc/apt/sources.list.d/teleport.list"
	aptTeleportPublicKeyFileRelative  = "/usr/share/keyrings/teleport-archive-keyring.asc"
)

// AddRepository adds the Teleport repository to the current system.
func (pm *packageManagerAPT) AddRepository(ctx context.Context, linuxInfo *linuxDistroInfo, repoChannel string) error {
	pm.logger.InfoContext(ctx, "Fetch repository key", "endpoint", aptPublicKeyEndpoint)

	resp, err := pm.HTTPClient.Get(aptPublicKeyEndpoint)
	if err != nil {
		return trace.Wrap(err)
	}
	defer resp.Body.Close()
	publicKey, err := utils.ReadAtMost(resp.Body, teleport.MaxHTTPResponseSize)
	if err != nil {
		return trace.Wrap(err)
	}

	aptTeleportSourceListFile := path.Join(pm.fsRootPrefix, aptTeleportSourceListFileRelative)
	aptTeleportPublicKeyFile := path.Join(pm.fsRootPrefix, aptTeleportPublicKeyFileRelative)
	// deb [signed-by=/usr/share/keyrings/teleport-archive-keyring.asc]  https://apt.releases.teleport.dev/${ID?} ${VERSION_CODENAME?} {{ .RepoChannel }}"
	teleportRepoMetadata := fmt.Sprintf("deb [signed-by=%s] %s%s %s %s\n", aptTeleportPublicKeyFile, aptRepoEndpoint, linuxInfo.ID, linuxInfo.VersionCodename, repoChannel)

	switch {
	case pm.legacy:
		pm.logger.InfoContext(ctx, "Trust key using apt-key add")
		aptKeyAddCMD := exec.CommandContext(ctx, "apt-key", "add", "-")
		aptKeyAddCMD.Stdin = bytes.NewReader(publicKey)
		aptKeyAddCMDOutput, err := aptKeyAddCMD.CombinedOutput()
		if err != nil {
			return trace.Wrap(err, string(aptKeyAddCMDOutput))
		}
		teleportRepoMetadata = fmt.Sprintf("deb %s %s %s", aptRepoEndpoint, linuxInfo.VersionCodename, repoChannel)

	default:
		if err := os.WriteFile(aptTeleportPublicKeyFile, publicKey, filePermsRepository); err != nil {
			return trace.Wrap(err)
		}
	}

	pm.logger.InfoContext(ctx, "Adding repository metadata", "apt_source_file", aptTeleportSourceListFile, "metadata", teleportRepoMetadata)
	if err := os.WriteFile(aptTeleportSourceListFile, []byte(teleportRepoMetadata), filePermsRepository); err != nil {
		return trace.Wrap(err)
	}

	pm.logger.InfoContext(ctx, "Updating apt sources")
	updateReposCMD := exec.CommandContext(ctx, "apt-get", "update")
	updateReposCMDOutput, err := updateReposCMD.CombinedOutput()
	if err != nil {
		return trace.Wrap(err, string(updateReposCMDOutput))
	}
	return nil
}

// InstallPackageVersion installs one or multiple packages into the current system.
func (pm *packageManagerAPT) InstallPackageVersion(ctx context.Context, packageList []packageVersion) error {
	if len(packageList) == 0 {
		return nil
	}

	aptInstallArgs := make([]string, 0, len(packageList)+2)
	aptInstallArgs = append(aptInstallArgs, "install", "-y")

	for _, pv := range packageList {
		if pv.Version != "" {
			aptInstallArgs = append(aptInstallArgs, pv.Name+"="+pv.Version)
			continue
		}
		aptInstallArgs = append(aptInstallArgs, pv.Name)
	}

	pm.logger.InfoContext(ctx, "Installing packages.", "packages", packageList)

	installPackagesCMD := exec.CommandContext(ctx, "apt-get", aptInstallArgs...)
	installPackagesCMDOutput, err := installPackagesCMD.CombinedOutput()
	if err != nil {
		return trace.Wrap(err, string(installPackagesCMDOutput))
	}
	return nil
}
