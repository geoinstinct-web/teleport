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

package common

import (
	"context"
	"log/slog"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/lib/install"
	"github.com/gravitational/teleport/lib/utils"
)

type installTeleportFlags struct {
	// RepositoryChannel is the repository channel to use.
	// Eg stable/cloud or stable/rolling
	RepositoryChannel string

	// Version is the binary version to install from the channel or from the tarball.
	// If using a repository, ensure that this version is available there.
	Version string

	// ProxyPublicAddr is the proxy public address that the instance will connect to.
	// Eg, https://example.platform.sh
	ProxyPublicAddr string

	// TokenName is the token name to be used by the instance to join the cluster.
	TokenName string

	// Enterprise indicates whether to install the OSS or the Enterprise variant of teleport.
	Enterprise bool

	// AutoUpgrades indicates whether the installed binaries should auto upgrade.
	// System must support systemd to enable AutoUpgrades.
	AutoUpgrades bool
}

// onInstallTeleport is the handler of the "install teleport" CLI command.
func onInstallTeleport(cfg installTeleportFlags) error {
	ctx := context.Background()
	// Ensure we print output to the user. LogLevel at this point was set to Error.
	utils.InitLogger(utils.LoggingForDaemon, slog.LevelInfo)

	teleportInstaller, err := install.NewInstaller(&install.InstallTeleportConfig{
		ProxyPublicAddr:   cfg.ProxyPublicAddr,
		TokenName:         cfg.TokenName,
		RepositoryChannel: cfg.RepositoryChannel,
		Version:           cfg.Version,
		Enterprise:        cfg.Enterprise,
		AutoUpgrades:      cfg.AutoUpgrades,
		FSRootPrefix:      "/",
	})
	if err != nil {
		return trace.Wrap(err)
	}

	return trace.Wrap(teleportInstaller.Install(ctx))
}
