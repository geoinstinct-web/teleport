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

package web

import (
	"context"
	"crypto/tls"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strconv"

	"github.com/julienschmidt/httprouter"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/websocket"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/srv/desktop"
	"github.com/gravitational/teleport/lib/srv/desktop/tdp"
	"github.com/gravitational/teleport/lib/utils"
)

// GET /webapi/sites/:site/desktops/:desktopName/connect?access_token=<bearer_token>&username=<username>&width=<width>&height=<height>
func (h *Handler) desktopConnectHandle(
	w http.ResponseWriter,
	r *http.Request,
	p httprouter.Params,
	ctx *SessionContext,
	site reversetunnel.RemoteSite,
) (interface{}, error) {
	desktopName := p.ByName("desktopName")
	if desktopName == "" {
		return nil, trace.BadParameter("missing desktopName in request URL")
	}

	log := ctx.log.WithField("desktop-name", desktopName)
	log.Debug("New desktop access websocket connection")

	if err := createDesktopConnection(w, r, desktopName, log, ctx, site, h); err != nil {
		log.Error(err)
		return nil, trace.Wrap(err)
	}

	return nil, nil
}

func createDesktopConnection(w http.ResponseWriter, r *http.Request, desktopName string, log *logrus.Entry, ctx *SessionContext, site reversetunnel.RemoteSite, h *Handler) error {
	q := r.URL.Query()
	username := q.Get("username")
	if username == "" {
		return trace.BadParameter("missing username")
	}
	width, err := strconv.Atoi(q.Get("width"))
	if err != nil {
		return trace.BadParameter("width missing or invalid")
	}
	height, err := strconv.Atoi(q.Get("height"))
	if err != nil {
		return trace.BadParameter("height missing or invalid")
	}

	log.Debugf("Attempting to connect to desktop using username=%v, width=%v, height=%v\n", username, width, height)

	winServices, err := ctx.unsafeCachedAuthClient.GetWindowsDesktopServices(r.Context())
	if err != nil {
		return trace.Wrap(err)
	}

	// TODO(awly): trusted cluster support - if this request is for a different
	// cluster, dial their proxy and forward the websocket request as is.

	if len(winServices) == 0 {
		return trace.NotFound("No windows_desktop_services are registered in this cluster")
	}
	// Pick a random Windows desktop service as our gateway.
	// When agent mode is implemented in the service, we'll have to filter out
	// the services in agent mode.
	//
	// In the future, we may want to do something smarter like latency-based
	// routing.
	service := winServices[rand.Intn(len(winServices))]
	log = log.WithField("windows-service-uuid", service.GetName())
	log = log.WithField("windows-service-addr", service.GetAddr())
	serviceCon, err := site.DialTCP(reversetunnel.DialParams{
		From:     &utils.NetAddr{AddrNetwork: "tcp", Addr: r.RemoteAddr},
		To:       &utils.NetAddr{AddrNetwork: "tcp", Addr: service.GetAddr()},
		ConnType: types.WindowsDesktopTunnel,
		ServerID: service.GetName() + "." + ctx.parent.clusterName,
	})
	if err != nil {
		return trace.WrapWithMessage(err, "failed to connect to windows_desktop_service at %q: %v", service.GetAddr(), err)
	}
	defer serviceCon.Close()

	pc, err := proxyClient(r.Context(), ctx, h.ProxyHostPort())
	if err != nil {
		return trace.Wrap(err)
	}
	defer pc.Close()

	_, err = pc.RootClusterName()
	if err != nil {
		return trace.Wrap(err)

	}

	websocket.Handler(func(conn *websocket.Conn) {
		tlsConfig, err := desktopTLSConfig(r.Context(), conn, pc, ctx, desktopName, username, site.GetName())
		if err != nil {
			writeError(err, conn, log)
			log.Error(err)
			return
		}
		serviceConTLS := tls.Client(serviceCon, tlsConfig)

		if err := serviceConTLS.Handshake(); err != nil {
			writeError(err, conn, log)
			log.Error(err)
			return
		}
		log.Debug("Connected to windows_desktop_service")
		tdpConn := tdp.NewConn(serviceConTLS)
		err = tdpConn.OutputMessage(tdp.ClientUsername{Username: username})
		if err != nil {
			writeError(err, conn, log)
			return
		}
		err = tdpConn.OutputMessage(tdp.ClientScreenSpec{Width: uint32(width), Height: uint32(height)})
		if err != nil {
			writeError(err, conn, log)
			return
		}
		if err := proxyWebsocketConn(conn, serviceConTLS); err != nil {
			log.WithError(err).Warningf("Error proxying a desktop protocol websocket to windows_desktop_service")
		}
	}).ServeHTTP(w, r)
	return nil
}

func writeError(err error, ws *websocket.Conn, log *logrus.Entry) {
	rdpConn := tdp.NewConn(ws)
	oerr := rdpConn.OutputMessage(tdp.Error{Message: err.Error()})
	log.Error(trace.NewAggregate(err, oerr))
}

func proxyClient(ctx context.Context, sessCtx *SessionContext, addr string) (*client.ProxyClient, error) {
	cfg, err := makeTeleportClientConfig(ctx, sessCtx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := cfg.ParseProxyHost(addr); err != nil {
		return nil, trace.Wrap(err)
	}
	tc, err := client.NewClient(cfg)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	pc, err := tc.ConnectToProxy(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return pc, nil
}

func desktopTLSConfig(ctx context.Context, ws *websocket.Conn, pc *client.ProxyClient, sessCtx *SessionContext, desktopName, username, siteName string) (*tls.Config, error) {
	priv, err := ssh.ParsePrivateKey(sessCtx.session.GetPriv())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	key, err := pc.IssueUserCertsWithMFA(ctx, client.ReissueParams{
		RouteToWindowsDesktop: proto.RouteToWindowsDesktop{
			DesktopServer: desktopName,
			Login:         username,
		},
		RouteToCluster: siteName,
		ExistingCreds: &client.Key{
			Pub:                 ssh.MarshalAuthorizedKey(priv.PublicKey()),
			Priv:                sessCtx.session.GetPriv(),
			Cert:                sessCtx.session.GetPub(),
			TLSCert:             sessCtx.session.GetTLSCert(),
			WindowsDesktopCerts: make(map[string][]byte),
		},
	}, promptMFAChallenge(ws))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	windowDesktopCerts, ok := key.WindowsDesktopCerts[desktopName]
	if !ok {
		return nil, trace.NotFound("failed to found windows desktop certificates for %q", desktopName)
	}
	certConf, err := tls.X509KeyPair(windowDesktopCerts, sessCtx.session.GetPriv())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tlsConfig, err := sessCtx.ClientTLSConfig()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tlsConfig.Certificates = []tls.Certificate{certConf}
	// Pass target desktop UUID via SNI.
	tlsConfig.ServerName = desktopName + desktop.SNISuffix
	return tlsConfig, nil
}

func proxyWebsocketConn(ws *websocket.Conn, con net.Conn) error {
	// Ensure we send binary frames to the browser.
	ws.PayloadType = websocket.BinaryFrame

	errs := make(chan error, 2)
	go func() {
		defer ws.Close()
		defer con.Close()

		_, err := io.Copy(ws, con)
		errs <- err
	}()
	go func() {
		defer ws.Close()
		defer con.Close()

		_, err := io.Copy(con, ws)
		errs <- err
	}()

	var retErrs []error
	for i := 0; i < 2; i++ {
		retErrs = append(retErrs, <-errs)
	}
	return trace.NewAggregate(retErrs...)
}
