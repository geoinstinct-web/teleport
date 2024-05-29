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
	"log/slog"
	"os"
	"os/exec"
	"path"
	"slices"
	"strings"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/cloud"
	"github.com/gravitational/teleport/lib/config"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/linux"
	"github.com/gravitational/teleport/lib/utils"
)

const (
	filePermsRepository = 0o644
)

// InstallTeleportConfig installs teleport into the current system.
type InstallTeleportConfig struct {
	Logger *slog.Logger

	// ProxyPublicAddr is the proxy public address that the instance will connect to.
	// Eg, https://example.platform.sh
	ProxyPublicAddr string

	// RepositoryChannel is the repository channel to use.
	// Eg stable/cloud or stable/rolling
	RepositoryChannel string

	// Version is the binary version to install from the channel or from the tarball.
	// If using a repository, ensure that this version is available there.
	Version string

	// Enterprise indicates whether to install the OSS or the Enterprise variant of teleport.
	Enterprise bool

	// AutoUpgrades indicates whether the installation should auto upgrade.
	// System must support systemd to enable AutoUpgrades.
	AutoUpgrades bool

	// TokenName is the token name to be used by the instance to join the cluster.
	TokenName string

	// FSRootPrefix is the prefix to use when reading operating system information and when installing teleport.
	// This is mostly used for testing without intering with
	FSRootPrefix string
}

func (c *InstallTeleportConfig) checkAndSetDefaults() error {
	if c == nil {
		return trace.BadParameter("install teleport config is required")
	}

	if c.ProxyPublicAddr == "" {
		return trace.BadParameter("proxy public addr is required")
	}

	if c.Logger == nil {
		c.Logger = slog.Default()
	}

	if c.RepositoryChannel == "" {
		c.RepositoryChannel = "stable/rolling"
	}

	if c.AutoUpgrades {
		if c.Version == "" {
			return trace.BadParameter("version is required when auto upgrades are enabled")
		}
		if !c.Enterprise {
			return trace.BadParameter("only enterprise binary supports auto upgrades")
		}
	}

	return nil
}

type packageVersion struct {
	Name    string
	Version string
}
type packageManager interface {
	AddRepository(ctx context.Context, ldi *linuxDistroInfo, repoChannel string) error
	InstallPackageVersion(context.Context, []packageVersion) error
}

// TeleportInstaller will install teleport in the current system.
type TeleportInstaller struct {
	*InstallTeleportConfig

	packageManagers map[packageManagerKind]packageManager
}

// NewInstaller returns a new TeleportInstaller.
func NewInstaller(cfg *InstallTeleportConfig) (*TeleportInstaller, error) {
	if err := cfg.checkAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	ti := &TeleportInstaller{
		InstallTeleportConfig: cfg,
	}

	ti.packageManagers = map[packageManagerKind]packageManager{
		packageManagerKindAPTLegacy: NewPackageManagerAPTLegacy(cfg.FSRootPrefix),
		packageManagerKindAPT:       NewPackageManagerAPT(cfg.FSRootPrefix),
		packageManagerKindYUM:       &packageManagerYUM{},
		packageManagerKindZypper:    &packageManagerZypper{},
	}

	return ti, nil
}

const (
	// exclusiveInstallFileLock is the name of the lockfile to be used when installing teleport.
	// Used for the default installers (see api/types/installers/{agentless,}installer.sh.tmpl/).
	exclusiveInstallFileLock = "/var/lock/teleport_install.lock"

	// etcOSReleaseFile is the location of the OS Release information.
	// This is valid for most linux distros, that rely on systemd.
	etcOSReleaseFile = "/etc/os-release"

	// defaultTeleportBinaryLocation is the default teleport binary location.
	defaultTeleportBinaryLocation = "/usr/local/bin/teleport"
)

// Install teleport in the current system.
func (ti *TeleportInstaller) Install(ctx context.Context) error {
	// Ensure only one installer is running by locking the same file as the script installers.
	unlockFn, err := utils.FSTryWriteLock(ti.buildAbsoluteFilePath(exclusiveInstallFileLock))
	if err != nil {
		return trace.BadParameter("Could not get lock %s. Either remove it or wait for the other installer to finish.", exclusiveInstallFileLock)
	}
	defer func() {
		if err := unlockFn(); err != nil {
			ti.Logger.WarnContext(ctx, "Failed to remove lock. Please remove it manually.", "file", exclusiveInstallFileLock)
		}
	}()

	// Check if teleport is already installed.
	if _, err := os.Stat(ti.buildAbsoluteFilePath(defaultTeleportBinaryLocation)); err == nil {
		ti.Logger.InfoContext(ctx, "Teleport is already installed in the system.")
		return nil
	}

	// Read current system information.
	linuxInfo, err := ti.linuxDistribution()
	if err != nil {
		return trace.Wrap(err)
	}

	ti.Logger.InfoContext(ctx, "Operating system detected.",
		"id", linuxInfo.ID,
		"id_like", linuxInfo.IDLike,
		"codename", linuxInfo.VersionCodename,
		"version_id", linuxInfo.VersionID,
	)

	// Pick up the correct package manager/repository for the system.
	packageManager, ok := ti.packageManagers[linuxInfo.packageManagerKind()]
	if !ok {
		return trace.BadParameter("package manager for %s (%s) is not yet supported", linuxInfo.ID, linuxInfo.IDLike)
	}
	if err := packageManager.AddRepository(ctx, linuxInfo, ti.RepositoryChannel); err != nil {
		return trace.BadParameter("failed to add teleport repository to system: %v", err)
	}

	teleportPackageName := types.PackageNameOSS
	if ti.Enterprise {
		teleportPackageName = types.PackageNameEnt
	}

	packagesToInstall := []packageVersion{{Name: teleportPackageName, Version: ti.Version}}
	if ti.AutoUpgrades {
		teleportAutoUpdaterPackage := teleportPackageName + "-updater"
		packagesToInstall = append(packagesToInstall, packageVersion{Name: teleportAutoUpdaterPackage, Version: ti.Version})
	}

	if err := packageManager.InstallPackageVersion(ctx, packagesToInstall); err != nil {
		return trace.BadParameter("failed to install teleport: %v", err)
	}

	// detect and fetch cloud provider metadata
	imdsClient, err := cloud.DiscoverInstanceMetadata(ctx)
	if err != nil {
		return trace.BadParameter("Could not determine cloud provider.")
	}
	ti.Logger.InfoContext(ctx, "Detected cloud provider.", "cloud", imdsClient.GetType())
	if !imdsClient.IsAvailable(ctx) {
		return trace.BadParameter("instance metadata is not available")
	}

	var joinMethod types.JoinMethod
	nodeLabels := make(map[string]string)

	switch imdsClient.GetType() {
	case types.InstanceMetadataTypeAzure:
		joinMethod = types.JoinMethodAzure
		nodeLabels[types.SubscriptionIDLabel] = ".compute.subscriptionId"
		nodeLabels[types.VMIDLabel] = ".compute.vmId"
		nodeLabels[types.RegionLabel] = ".compute.location"
		nodeLabels[types.ResourceGroupLabel] = ".compute.resourceGroupName"

	case types.InstanceMetadataTypeEC2:
		joinMethod = types.JoinMethodIAM
		nodeLabels[types.AWSInstanceIDLabel] = "instance id"
		nodeLabels[types.AWSAccountIDLabel] = "account id"

	case types.InstanceMetadataTypeGCP:
		joinMethod = types.JoinMethodGCP
		nodeLabels[types.NameLabel] = "/computeMetadata/v1/instance/name"
		nodeLabels[types.ZoneLabel] = "/computeMetadata/v1/instance/zone"
		nodeLabels[types.ProjectIDLabel] = "computeMetadata/v1/project/project-id"

	default:
		return trace.BadParameter("Unsupported cloud provider: %v", imdsClient.GetType())
	}

	labelEntries := make([]string, 0, len(nodeLabels))
	for labelKey, labelValue := range nodeLabels {
		labelEntries = append(labelEntries, labelKey+"="+labelValue)
	}
	nodeLabelsCommaSeperated := strings.Join(labelEntries, ",")

	fileConfig, err := config.MakeSampleFileConfig(config.SampleFlags{
		ProxyAddress: ti.ProxyPublicAddr,
		JoinMethod:   string(joinMethod),
		AuthToken:    ti.TokenName,
		NodeLabels:   nodeLabelsCommaSeperated,
		Roles:        defaults.RoleNode,
	})
	if err != nil {
		return trace.Wrap(err)
	}

	teleportYamlConfig := fileConfig.DebugDumpToYAML()

	configFilePath := ti.buildAbsoluteFilePath(defaults.ConfigFilePath)
	ti.Logger.InfoContext(ctx, "Writing teleport configuration", "file", configFilePath, "contents", teleportYamlConfig)

	if err := os.WriteFile(configFilePath, []byte(teleportYamlConfig), filePermsRepository); err != nil {
		return trace.Wrap(err)
	}

	ti.Logger.InfoContext(ctx, "Starting teleport service via systemd")
	systemctlEnableNowCMD := exec.CommandContext(ctx, "systemctl", "enable", "--now", "teleport")
	systemctlEnableNowCMDOutput, err := systemctlEnableNowCMD.CombinedOutput()
	if err != nil {
		return trace.Wrap(err, string(systemctlEnableNowCMDOutput))
	}

	return nil
}

// open opens the file path using the FSRootPrefix
// Caller must close the file.
func (ti *TeleportInstaller) buildAbsoluteFilePath(filepath string) string {
	return path.Join(ti.FSRootPrefix, filepath)
}

type linuxDistroInfo struct {
	*linux.OSRelease
}

func (l *linuxDistroInfo) packageManagerKind() packageManagerKind {
	aptWellKnownIDs := []string{"debian", "ubuntu"}
	if slices.Contains(aptWellKnownIDs, l.ID) || slices.Contains(aptWellKnownIDs, l.IDLike) {
		legacyAPT := l.VersionCodename == "xenial" || l.VersionCodename == "trusty"
		if legacyAPT {
			return packageManagerKindAPTLegacy
		}
		return packageManagerKindAPT
	}

	yumWellKnownIDs := []string{"amzn", "rhel"}
	if slices.Contains(yumWellKnownIDs, l.ID) || slices.Contains(yumWellKnownIDs, l.IDLike) {
		return packageManagerKindYUM
	}

	zypperWellKnownIDs := []string{"sles", "opensuse-tumbleweed", "opensuse-leap"}
	if slices.Contains(zypperWellKnownIDs, l.ID) || slices.Contains(zypperWellKnownIDs, l.IDLike) {
		return packageManagerKindZypper
	}

	return packageManagerKindUnknown
}

// linuxDistribution reads the current file system to detect the Linux Distro and Version of the current system.
//
// https://www.freedesktop.org/software/systemd/man/latest/os-release.html
func (ti *TeleportInstaller) linuxDistribution() (*linuxDistroInfo, error) {
	f, err := os.Open(ti.buildAbsoluteFilePath(etcOSReleaseFile))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer f.Close()

	osRelease, err := linux.ParseOSReleaseFromReader(f)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &linuxDistroInfo{
		OSRelease: osRelease,
	}, nil
}

type packageManagerKind int

const (
	packageManagerKindUnknown = iota
	packageManagerKindAPTLegacy
	packageManagerKindAPT
	packageManagerKindYUM
	packageManagerKindZypper
)
