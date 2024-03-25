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

package aws

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/httplib"
	"github.com/gravitational/teleport/lib/httplib/reverseproxy"
	"github.com/gravitational/teleport/lib/srv/app/common"
	"github.com/gravitational/teleport/lib/utils"
	awsutils "github.com/gravitational/teleport/lib/utils/aws"
)

// signerHandler is an http.Handler for signing and forwarding requests to AWS API.
type signerHandler struct {
	// fwd is a Forwarder used to forward signed requests to AWS API.
	fwd *reverseproxy.Forwarder
	// SignerHandlerConfig is the configuration for the handler.
	SignerHandlerConfig
	// closeContext is the app server close context.
	closeContext context.Context
}

// SignerHandlerConfig is the awsSignerHandler configuration.
type SignerHandlerConfig struct {
	// Log is a logger for the handler.
	Log logrus.FieldLogger
	// RoundTripper is an http.RoundTripper instance used for requests.
	RoundTripper http.RoundTripper
	// SigningService is used to sign requests before forwarding them.
	*awsutils.SigningService
	// Clock is used to override time in tests.
	Clock clockwork.Clock
}

// CheckAndSetDefaults validates the AwsSignerHandlerConfig.
func (cfg *SignerHandlerConfig) CheckAndSetDefaults() error {
	if cfg.SigningService == nil {
		return trace.BadParameter("missing SigningService")
	}
	if cfg.RoundTripper == nil {
		tr, err := defaults.Transport()
		if err != nil {
			return trace.Wrap(err)
		}
		cfg.RoundTripper = tr
	}
	if cfg.Log == nil {
		cfg.Log = logrus.WithField(teleport.ComponentKey, "aws:signer")
	}
	if cfg.Clock == nil {
		cfg.Clock = clockwork.NewRealClock()
	}
	return nil
}

// NewAWSSignerHandler creates a new request handler for signing and forwarding requests to AWS API.
func NewAWSSignerHandler(ctx context.Context, config SignerHandlerConfig) (http.Handler, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	handler := &signerHandler{
		SignerHandlerConfig: config,
		closeContext:        ctx,
	}

	var err error
	handler.fwd, err = reverseproxy.New(
		reverseproxy.WithRoundTripper(config.RoundTripper),
		reverseproxy.WithLogger(config.Log),
		reverseproxy.WithErrorHandler(handler.formatForwardResponseError),
	)

	return handler, trace.Wrap(err)
}

// formatForwardResponseError converts an error to a status code and writes the code to a response.
func (s *signerHandler) formatForwardResponseError(rw http.ResponseWriter, r *http.Request, err error) {
	s.Log.WithError(err).Debugf("Failed to process request.")
	common.SetTeleportAPIErrorHeader(rw, err)

	// Convert trace error type to HTTP and write response.
	code := trace.ErrorToCode(err)
	http.Error(rw, http.StatusText(code), code)
}

// ServeHTTP handles incoming requests by signing them and then forwarding them to the proper AWS API.
func (s *signerHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if err := s.serveHTTP(w, req); err != nil {
		s.formatForwardResponseError(w, req, err)
		return
	}
}

// serveHTTP is a helper to simplify error handling in ServeHTTP.
func (s *signerHandler) serveHTTP(w http.ResponseWriter, req *http.Request) error {
	sessCtx, err := common.GetSessionContext(req)
	if err != nil {
		return trace.Wrap(err)
	}

	// Handle requests signed with real credentials of assumed roles by the AWS
	// client. Headers will be restored and the request will be forwarded to
	// AWS without re-signing.
	if req.Header.Get(common.TeleportAWSAssumedRole) != "" {
		return trace.Wrap(s.serveRequestByAssumedRole(sessCtx, w, req))
	}

	// Handle requests signed with the default local proxy credentials. The
	// request will be re-signed with real credentials by assuming the
	// requested role of this AWS app.
	return trace.Wrap(s.serveCommonRequest(sessCtx, w, req))
}

func (s *signerHandler) serveCommonRequest(sessCtx *common.SessionContext, w http.ResponseWriter, req *http.Request) error {
	// It's important that we resolve the endpoint before modifying the request headers,
	// as they may be needed to resolve the endpoint correctly.
	re, err := ResolveEndpoint(req)
	if err != nil {
		return trace.Wrap(err)
	}

	unsignedReq, responseExtraHeaders, err := RewriteCommonRequest(s.closeContext, s.Clock, sessCtx, req, re)
	if err != nil {
		return trace.Wrap(err)
	}

	signedReq, err := s.SignRequest(s.closeContext, unsignedReq,
		&awsutils.SigningCtx{
			SigningName:   re.SigningName,
			SigningRegion: re.SigningRegion,
			Expiry:        sessCtx.Identity.Expires,
			SessionName:   sessCtx.Identity.Username,
			AWSRoleArn:    sessCtx.Identity.RouteToApp.AWSRoleARN,
			AWSExternalID: sessCtx.App.GetAWSExternalID(),
		})
	if err != nil {
		return trace.Wrap(err)
	}
	recorder := httplib.NewResponseStatusRecorder(w)

	for headerKey, headerValue := range responseExtraHeaders {
		w.Header().Set(headerKey, strings.Join(headerValue, ";"))
	}

	s.fwd.ServeHTTP(recorder, signedReq)
	EmitAudit(s.closeContext, sessCtx, unsignedReq, uint32(recorder.Status()), re)
	return nil
}

// serveRequestByAssumedRole forwards the requests signed with real credentials
// of an assumed role to AWS.
func (s *signerHandler) serveRequestByAssumedRole(sessCtx *common.SessionContext, w http.ResponseWriter, req *http.Request) error {
	re, err := resolveEndpointByXForwardedHost(req, common.TeleportAWSAssumedRoleAuthorization)
	if err != nil {
		return trace.Wrap(err)
	}

	req, err = s.rewriteRequestByAssumedRole(req, re)
	if err != nil {
		return trace.Wrap(err)
	}

	reqCloneForAudit, err := cloneRequest(req)
	if err != nil {
		return trace.Wrap(err)
	}

	recorder := httplib.NewResponseStatusRecorder(w)
	s.fwd.ServeHTTP(recorder, req)
	if err := EmitAudit(s.closeContext, sessCtx, reqCloneForAudit, uint32(recorder.Status()), re); err != nil {
		// log but don't return the error, because we already handed off request/response handling to the oxy forwarder.
		s.Log.WithError(err).Warn("Failed to emit audit event.")
	}
	return nil
}

func EmitAudit(ctx context.Context, sessCtx *common.SessionContext, req *http.Request, status uint32, re *endpoints.ResolvedEndpoint) error {
	if isDynamoDBEndpoint(re) {
		return sessCtx.Audit.OnDynamoDBRequest(ctx, sessCtx, req, status, re)
	}

	return sessCtx.Audit.OnRequest(ctx, sessCtx, req, status, re)
}

// rewriteRequest clones a request to rewrite the url.
func rewriteRequest(ctx context.Context, r *http.Request, re *endpoints.ResolvedEndpoint) (*http.Request, error) {
	u, err := urlForResolvedEndpoint(r, re)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// clone the request for rewriting
	outReq := r.Clone(ctx)
	if outReq.URL == nil {
		outReq.URL = u
	} else {
		outReq.URL.Scheme = "https"
		outReq.URL.Host = u.Host
	}
	outReq.Body = http.NoBody
	if r.Body != nil {
		outReq.Body = io.NopCloser(io.LimitReader(r.Body, teleport.MaxHTTPRequestSize))
	}
	// need to rewrite the host header as well. The oxy forwarder will do this for us,
	// since we use the PassHostHeader(false) option, but if host is a signed header
	// then we must make the host match the URL host before signing the request or AWS
	// will reject the request for failing sigv4 verification.
	outReq.Host = u.Host
	return outReq, nil
}

// RewriteCommonRequest updates request signed with the default local proxy credentials.
// The returned headers must be added to the response headers.
func RewriteCommonRequest(ctx context.Context, clock clockwork.Clock, sessCtx *common.SessionContext, r *http.Request, re *endpoints.ResolvedEndpoint) (*http.Request, http.Header, error) {
	req, err := rewriteRequest(ctx, r, re)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	var responseExtraHeaders http.Header
	if strings.EqualFold(re.SigningName, sts.EndpointsID) {
		responseExtraHeaders, err = updateAssumeRoleDuration(sessCtx.Identity, req, clock)
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}
	}
	return req, responseExtraHeaders, nil
}

// rewriteRequestByAssumedRole updates headers and url for requests by assumed roles.
func (s *signerHandler) rewriteRequestByAssumedRole(r *http.Request, re *endpoints.ResolvedEndpoint) (*http.Request, error) {
	req, err := rewriteRequest(s.closeContext, r, re)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if r.Host != req.Host {
		return nil, trace.BadParameter("resolved host %q does not match requested host %q", req.Host, r.Host)
	}

	// Remove the special header before sending the request to AWS.
	assumedRole := req.Header.Get(common.TeleportAWSAssumedRole)
	req.Header.Del(common.TeleportAWSAssumedRole)

	// Put back the original authorization header.
	utils.RenameHeader(req.Header, common.TeleportAWSAssumedRoleAuthorization, awsutils.AuthorizationHeader)
	return common.WithAWSAssumedRole(req, assumedRole), nil
}

// urlForResolvedEndpoint creates a URL based on input request and resolved endpoint.
func urlForResolvedEndpoint(r *http.Request, re *endpoints.ResolvedEndpoint) (*url.URL, error) {
	resolvedURL, err := url.Parse(re.URL)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Replaces scheme and host. Keeps original path etc.
	clone := *r.URL
	if resolvedURL.Host != "" {
		clone.Host = resolvedURL.Host
	}
	if resolvedURL.Scheme != "" {
		clone.Scheme = resolvedURL.Scheme
	}
	return &clone, nil
}

// cloneRequest makes a clone of the request with a deep-cloned body.
func cloneRequest(req *http.Request) (*http.Request, error) {
	body, err := utils.GetAndReplaceRequestBody(req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	clone := req.Clone(req.Context())
	clone.Body = io.NopCloser(bytes.NewReader(body))
	return clone, nil
}
