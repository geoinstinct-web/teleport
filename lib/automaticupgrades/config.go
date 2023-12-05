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

package automaticupgrades

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	// automaticUpgradesEnvar defines the env var to lookup when deciding whether to enable AutomaticUpgrades feature.
	automaticUpgradesEnvar = "TELEPORT_AUTOMATIC_UPGRADES"

	// automaticUpgradesChannelEnvar defines a customer automatic upgrades version release channel.
	automaticUpgradesChannelEnvar = "TELEPORT_AUTOMATIC_UPGRADES_CHANNEL"

	// teleportUpgradeScript defines the default teleport-upgrade script path
	teleportUpgradeScript = "/usr/sbin/teleport-upgrade"
)

// IsEnabled reads the TELEPORT_AUTOMATIC_UPGRADES and returns whether Automatic Upgrades are enabled or disabled.
// An error is logged (warning) if the variable is present but its value could not be converted into a boolean.
// Acceptable values for TELEPORT_AUTOMATIC_UPGRADES are:
// 1, t, T, TRUE, true, True, 0, f, F, FALSE, false, False
func IsEnabled() bool {
	autoUpgradesEnv := os.Getenv(automaticUpgradesEnvar)
	if autoUpgradesEnv == "" {
		return false
	}

	automaticUpgrades, err := strconv.ParseBool(autoUpgradesEnv)
	if err != nil {
		log.Warnf("unexpected value for ENV:%s: %v", automaticUpgradesEnvar, err)
		return false
	}

	return automaticUpgrades
}

// GetChannel returns the TELEPORT_AUTOMATIC_UPGRADES_CHANNEL value.
// Example of an acceptable value for TELEPORT_AUTOMATIC_UPGRADES_CHANNEL is:
// https://updates.releases.teleport.dev/v1/stable/cloud
func GetChannel() string {
	return os.Getenv(automaticUpgradesChannelEnvar)
}

// GetUpgraderVersion returns the teleport upgrader version
func GetUpgraderVersion(ctx context.Context) string {
	if os.Getenv("TELEPORT_EXT_UPGRADER") == "unit" {
		out, err := exec.CommandContext(ctx, teleportUpgradeScript, "version").Output()
		if err != nil {
			log.WithError(err).Debug("Failed to exec teleport-upgrade version command.")
		} else {
			if version := strings.TrimSpace(string(out)); version != "" {
				return version
			}
		}
	}
	return os.Getenv("TELEPORT_EXT_UPGRADER_VERSION")
}
