/**
 * Copyright 2021 Gravitational, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package web

import (
	"net/http"

	"github.com/gravitational/trace"
	"github.com/julienschmidt/httprouter"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/web/ui"
)

// clusterKubesGet returns a list of kube clusters in a form the UI can present.
func (h *Handler) clusterKubesGet(w http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext, site reversetunnel.RemoteSite) (interface{}, error) {
	clt, err := sctx.GetUserClient(r.Context(), site)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	accessChecker, err := sctx.GetUserAccessChecker()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	resp, err := handleClusterKubesGet(clt, r, accessChecker.Roles())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return resp, nil
}

// clusterDatabasesGet returns a list of db servers in a form the UI can present.
func (h *Handler) clusterDatabasesGet(w http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext, site reversetunnel.RemoteSite) (interface{}, error) {
	clt, err := sctx.GetUserClient(r.Context(), site)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	res, err := handleClusterDatabasesGet(clt, r, h.auth.clusterName)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return res, nil
}

// clusterDesktopsGet returns a list of desktops in a form the UI can present.
func (h *Handler) clusterDesktopsGet(w http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext, site reversetunnel.RemoteSite) (interface{}, error) {
	clt, err := sctx.GetUserClient(r.Context(), site)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	accessChecker, err := sctx.GetUserAccessChecker()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	res, err := handleClusterDesktopsGet(clt, accessChecker.Roles(), r)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return res, nil
}

// clusterDesktopServicesGet returns a list of desktop services in a form the UI can present.
func (h *Handler) clusterDesktopServicesGet(w http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext, site reversetunnel.RemoteSite) (interface{}, error) {
	// Get a client to the Auth Server with the logged in user's identity. The
	// identity of the logged in user is used to fetch the list of desktop services.
	clt, err := sctx.GetUserClient(r.Context(), site)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	resp, err := listResources(clt, r, types.KindWindowsDesktopService)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	desktopServices, err := types.ResourcesWithLabels(resp.Resources).AsWindowsDesktopServices()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return listResourcesGetResponse{
		Items:      ui.MakeDesktopServices(desktopServices),
		StartKey:   &resp.NextKey,
		TotalCount: &resp.TotalCount,
	}, nil
}

// getDesktopHandle returns a desktop.
func (h *Handler) getDesktopHandle(w http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext, site reversetunnel.RemoteSite) (interface{}, error) {
	clt, err := sctx.GetUserClient(r.Context(), site)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	desktopName := p.ByName("desktopName")

	windowsDesktops, err := clt.GetWindowsDesktops(r.Context(),
		types.WindowsDesktopFilter{Name: desktopName})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if len(windowsDesktops) == 0 {
		return nil, trace.NotFound("expected at least 1 desktop, got 0")
	}

	accessChecker, err := sctx.GetUserAccessChecker()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// windowsDesktops may contain the same desktop multiple times
	// if multiple Windows Desktop Services are in use. We only need
	// to see the desktop once in the UI, so just take the first one.
	uiDesktop, err := ui.MakeDesktop(windowsDesktops[0], accessChecker.Roles())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return uiDesktop, nil
}

// desktopIsActive checks if a desktop has an active session and returns a desktopIsActive.
//
// GET /v1/webapi/sites/:site/desktops/:desktopName/active
//
// Response body:
//
// {"active": bool}
func (h *Handler) desktopIsActive(w http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext, site reversetunnel.RemoteSite) (interface{}, error) {
	desktopName := p.ByName("desktopName")
	trackers, err := h.auth.proxyClient.GetActiveSessionTrackersWithFilter(r.Context(), &types.SessionTrackerFilter{
		Kind: string(types.WindowsDesktopSessionKind),
		State: &types.NullableSessionState{
			State: types.SessionState_SessionStateRunning,
		},
		DesktopName: desktopName,
	})

	if err != nil {
		return nil, trace.Wrap(err)
	}

	clt, err := sctx.GetUserClient(r.Context(), site)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	for _, tracker := range trackers {
		// clt is an auth.ClientI with the role of the user, so
		// clt.GetWindowsDesktops() can be used to confirm that
		// the user has access to the requested desktop.
		desktops, err := clt.GetWindowsDesktops(r.Context(),
			types.WindowsDesktopFilter{Name: tracker.GetDesktopName()})
		if err != nil {
			return nil, trace.Wrap(err)
		}

		if len(desktops) == 0 {
			// There are no active sessions for this desktop
			// or the user doesn't have access to it
			break
		} else {
			return desktopIsActive{true}, nil
		}
	}

	return desktopIsActive{false}, nil
}

type desktopIsActive struct {
	Active bool `json:"active"`
}
