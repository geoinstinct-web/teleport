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

package web

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gravitational/trace"
	"github.com/julienschmidt/httprouter"

	"github.com/gravitational/teleport/lib/automaticupgrades"
	"github.com/gravitational/teleport/lib/automaticupgrades/constants"
	"github.com/gravitational/teleport/lib/automaticupgrades/version"
)

const defaultChannelTimeout = 5 * time.Second

// automaticUpgrades implements a version server in the Teleport Proxy.
// It is configured through the Teleport Proxy configuration and tells agent updaters
// which version they should install.
func (h *Handler) automaticUpgrades(w http.ResponseWriter, r *http.Request, p httprouter.Params) (interface{}, error) {
	if h.cfg.AutomaticUpgradesChannels == nil {
		return nil, trace.AccessDenied("This proxy is not configured to serve automatic upgrades channels.")
	}

	// The request format is "<channel name>/{version,critical}"
	// As <channel name> might contain "/" we have to split, pop the last part
	// and re-construct the channel name.
	channelAndType := p.ByName("request")

	reqParts := strings.Split(strings.Trim(channelAndType, "/"), "/")
	if len(reqParts) < 2 {
		return nil, trace.BadParameter("path format should be /webapi/automaticupgrades/channel/<channel>/{version,critical}")
	}
	requestType := reqParts[len(reqParts)-1]
	channelName := strings.Join(reqParts[:len(reqParts)-1], "/")

	if channelName == "" {
		return nil, trace.BadParameter("a channel name is required")
	}

	// We check if the channel is configured
	channel, ok := h.cfg.AutomaticUpgradesChannels[channelName]
	if !ok {
		return nil, trace.NotFound("channel %s not found", channelName)
	}

	// Finally, we treat the request based on its type
	switch requestType {
	case "version":
		h.log.Debugf("Agent requesting version for channel %s", channelName)
		return h.automaticUpgradesVersion(w, r, channel)
	case "critical":
		h.log.Debugf("Agent requesting criticality for channel %s", channelName)
		return h.automaticUpgradesCritical(w, r, channel)
	default:
		return nil, trace.BadParameter("requestType path must end with 'version' or 'critical'")
	}
}

// automaticUpgradesVersion handles version requests from upgraders
func (h *Handler) automaticUpgradesVersion(w http.ResponseWriter, r *http.Request, channel *automaticupgrades.Channel) (interface{}, error) {
	ctx, cancel := context.WithTimeout(r.Context(), defaultChannelTimeout)
	defer cancel()

	targetVersion, err := channel.GetVersion(ctx)
	if err != nil {
		// If the error is that the upstream channel has no version
		// We gracefully handle by serving "none"
		var NoNewVersionErr *version.NoNewVersionError
		if errors.As(trace.Unwrap(err), &NoNewVersionErr) {
			_, err = w.Write([]byte(constants.NoVersion))
			return nil, trace.Wrap(err)
		}
		// Else we propagate the error
		return nil, trace.Wrap(err)
	}

	_, err = w.Write([]byte(targetVersion))
	return nil, trace.Wrap(err)
}

// automaticUpgradesCritical handles criticality requests from upgraders
func (h *Handler) automaticUpgradesCritical(w http.ResponseWriter, r *http.Request, channel *automaticupgrades.Channel) (interface{}, error) {
	ctx, cancel := context.WithTimeout(r.Context(), defaultChannelTimeout)
	defer cancel()

	critical, err := channel.GetCritical(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	response := "no"
	if critical {
		response = "yes"
	}
	_, err = w.Write([]byte(response))
	return nil, trace.Wrap(err)
}
