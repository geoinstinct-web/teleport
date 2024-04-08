/*
Copyright 2022 Gravitational, Inc.

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

package client

import (
	"context"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/client/proto"
	devicetrustv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/devicetrust/v1"
)

// JoinServiceClient is a client for the JoinService, which runs on both the
// auth and proxy.
type JoinServiceClient struct {
	grpcClient proto.JoinServiceClient
}

// NewJoinServiceClient returns a new JoinServiceClient wrapping the given grpc
// client.
func NewJoinServiceClient(grpcClient proto.JoinServiceClient) *JoinServiceClient {
	return &JoinServiceClient{
		grpcClient: grpcClient,
	}
}

// RegisterIAMChallengeResponseFunc is a function type meant to be passed to
// RegisterUsingIAMMethod. It must return a *proto.RegisterUsingIAMMethodRequest
// for a given challenge, or an error.
type RegisterIAMChallengeResponseFunc func(challenge string) (*proto.RegisterUsingIAMMethodRequest, error)

// RegisterAzureChallengeResponseFunc is a function type meant to be passed to
// RegisterUsingAzureMethod. It must return a
// *proto.RegisterUsingAzureMethodRequest for a given challenge, or an error.
type RegisterAzureChallengeResponseFunc func(challenge string) (*proto.RegisterUsingAzureMethodRequest, error)

type RegisterTPMChallengeResponseFunc func(challenge *devicetrustv1.TPMEncryptedCredential) (*proto.RegisterUsingTPMMethodChallengeResponse, error)

// RegisterUsingIAMMethod registers the caller using the IAM join method and
// returns signed certs to join the cluster.
//
// The caller must provide a ChallengeResponseFunc which returns a
// *types.RegisterUsingTokenRequest with a signed sts:GetCallerIdentity request
// including the challenge as a signed header.
func (c *JoinServiceClient) RegisterUsingIAMMethod(ctx context.Context, challengeResponse RegisterIAMChallengeResponseFunc) (*proto.Certs, error) {
	// Make sure the gRPC stream is closed when this returns
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// initiate the streaming rpc
	iamJoinClient, err := c.grpcClient.RegisterUsingIAMMethod(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// wait for the challenge string from auth
	challenge, err := iamJoinClient.Recv()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// get challenge response from the caller
	req, err := challengeResponse(challenge.Challenge)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// forward the challenge response from the caller to auth
	if err := iamJoinClient.Send(req); err != nil {
		return nil, trace.Wrap(err)
	}

	// wait for the certs from auth and return to the caller
	certsResp, err := iamJoinClient.Recv()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return certsResp.Certs, nil
}

// RegisterUsingAzureMethod registers the caller using the Azure join method and
// returns signed certs to join the cluster.
//
// The caller must provide a ChallengeResponseFunc which returns a
// *proto.RegisterUsingAzureMethodRequest with a signed attested data document
// including the challenge as a nonce.
func (c *JoinServiceClient) RegisterUsingAzureMethod(ctx context.Context, challengeResponse RegisterAzureChallengeResponseFunc) (*proto.Certs, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	azureJoinClient, err := c.grpcClient.RegisterUsingAzureMethod(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	challenge, err := azureJoinClient.Recv()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	req, err := challengeResponse(challenge.Challenge)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := azureJoinClient.Send(req); err != nil {
		return nil, trace.Wrap(err)
	}

	certsResp, err := azureJoinClient.Recv()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return certsResp.Certs, nil
}

// RegisterUsingTPMMethod ,,,
func (c *JoinServiceClient) RegisterUsingTPMMethod(ctx context.Context, initReq *proto.RegisterUsingTPMMethodInitialRequest, solveChallenge RegisterTPMChallengeResponseFunc) (*proto.Certs, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	tpmJoinClient, err := c.grpcClient.RegisterUsingTPMMethod(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	err = tpmJoinClient.Send(&proto.RegisterUsingTPMMethodRequest{
		Payload: &proto.RegisterUsingTPMMethodRequest_Init{
			Init: initReq,
		},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	challengeResp, err := tpmJoinClient.Recv()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	challenge, ok := challengeResp.Payload.(*proto.RegisterUsingTPMMethodResponse_ChallengeRequest)
	if !ok {
		return nil, trace.BadParameter(
			"unexpected payload type %T, expected *RegisterUsingTPMMethodResponse_ChallengeRequest",
			challengeResp.Payload,
		)
	}

	solution, err := solveChallenge(challenge.ChallengeRequest)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	err = tpmJoinClient.Send(&proto.RegisterUsingTPMMethodRequest{
		Payload: &proto.RegisterUsingTPMMethodRequest_ChallengeResponse{
			ChallengeResponse: solution,
		},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	certsResp, err := tpmJoinClient.Recv()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	certs, ok := certsResp.Payload.(*proto.RegisterUsingTPMMethodResponse_Certs)
	if !ok {
		return nil, trace.BadParameter(
			"unexpected payload type %T, expected *RegisterUsingTPMMethodResponse_Certs",
			certsResp.Payload,
		)
	}

	return certs.Certs, nil
}
