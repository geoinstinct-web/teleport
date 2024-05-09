//go:build !darwin
// +build !darwin

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
	"github.com/alecthomas/kingpin/v2"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/lib/vnet"
)

func newVnetCommand(app *kingpin.Application) vnetNotSupported {
	return vnetNotSupported{}
}

func newVnetAdminSetupCommand(app *kingpin.Application) vnetNotSupported {
	return vnetNotSupported{}
}

type vnetNotSupported struct{}

func (vnetNotSupported) FullCommand() string {
	return ""
}
func (vnetNotSupported) run(*CLIConf) error {
	return trace.Wrap(vnet.ErrVnetNotImplemented)
}
