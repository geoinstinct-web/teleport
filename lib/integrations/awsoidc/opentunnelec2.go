/*
Copyright 2023 Gravitational, Inc.

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

package awsoidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	signer "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2instanceconnect"
	"github.com/gorilla/websocket"
	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
	"golang.org/x/exp/slices"
)

var (
	// validEC2Ports contains the available EC2 ports to use with EC2 Instance Connect Endpoint.
	validEC2Ports = []string{"22", "3389"}

	// filterEC2InstanceConnectEndpointStateKey is the filter key for filtering EC2 Instance Connection Endpoint by their state.
	filterEC2InstanceConnectEndpointStateKey = "state"
	// filterEC2InstanceConnectEndpointVPCIDKey is the filter key for filtering EC2 Instance Connection Endpoint by their VPC ID.
	filterEC2InstanceConnectEndpointVPCIDKey = "vpc-id"
)

const (
	// hashForGetRequests is the SHA-256 for an empty element.
	// PresignHTTP requires the hash of the body, but this is a GET request and has no body.
	// https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
	hashForGetRequests = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// OpenTunnelEC2Request contains the required fields to open a tunnel to an EC2 instance.
// This will create a TCP socket that forwards incoming connections to the EC2's private IP address.
type OpenTunnelEC2Request struct {
	// Region is the AWS Region.
	Region string

	// InstanceID is the EC2 Instance's ID.
	InstanceID string

	// VPCID is the VPC where the EC2 Instance is located.
	// Used to look for the EC2 Instance Connect Endpoint.
	// Each VPC ID can only have one EC2 Instance Connect Endpoint.
	VPCID string

	// EC2SSHLoginUser is the OS user to use when the user wants SSH access.
	EC2SSHLoginUser string

	// EC2Address is the address to connect to in the EC2 Instance.
	// Eg, ip-172-31-32-234.eu-west-2.compute.internal:22
	EC2Address string

	// ec2OpenSSHPort is the port to connect to in the EC2 Instance.
	// This value is parsed from EC2Address.
	// Possible values: 22, 3389.
	ec2OpenSSHPort string

	// ec2PrivateHostname is the private hostname of the EC2 Instance.
	// This value is parsed from EC2Address.
	ec2PrivateHostname string

	// websocketCustomCA is a x509.Certificate to trust when trying to connect to the websocket.
	// For testing purposes only.
	websocketCustomCA *x509.Certificate
}

// CheckAndSetDefaults checks if the required fields are present.
func (r *OpenTunnelEC2Request) CheckAndSetDefaults() error {
	var err error

	if r.Region == "" {
		return trace.BadParameter("region is required")
	}

	if r.InstanceID == "" {
		return trace.BadParameter("instance id is required")
	}

	if r.VPCID == "" {
		return trace.BadParameter("vpcid is required")
	}

	if r.EC2SSHLoginUser == "" {
		return trace.BadParameter("ec2 ssh login user is required")
	}

	if r.EC2Address == "" {
		return trace.BadParameter("ec2 address required")
	}

	r.ec2PrivateHostname, r.ec2OpenSSHPort, err = net.SplitHostPort(r.EC2Address)
	if err != nil {
		return trace.BadParameter("ec2 address is invalid: %v", err)
	}

	if !slices.Contains(validEC2Ports, r.ec2OpenSSHPort) {
		return trace.BadParameter("invalid ec2 address port %s, possible values: %v", r.ec2OpenSSHPort, validEC2Ports)
	}

	return nil
}

// OpenTunnelEC2Response contains the response for creating a Tunnel to an EC2 Instance.
// It returns the listening address and the SSH Private Key (PEM encoded).
type OpenTunnelEC2Response struct {
	// SSHSigner is the SSH Signer that should be used to connect to the host.
	SSHSigner ssh.Signer

	// Tunnel is a net.Conn that is connected to the EC2 instance.
	// The SSH Client must use this connection to connect to it.
	Tunnel net.Conn
}

// OpenTunnelEC2Client describes the required methods to Open a Tunnel to an EC2 Instance using
// EC2 Instance Connect Endpoint.
type OpenTunnelEC2Client interface {
	// DescribeInstanceConnectEndpoints describes the specified EC2 Instance Connect Endpoints or all EC2 Instance
	// Connect Endpoints.
	DescribeInstanceConnectEndpoints(ctx context.Context, params *ec2.DescribeInstanceConnectEndpointsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstanceConnectEndpointsOutput, error)

	// SendSSHPublicKey pushes an SSH public key to the specified EC2 instance for use by the specified
	// user. The key remains for 60 seconds. For more information, see Connect to your
	// Linux instance using EC2 Instance Connect (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Connect-using-EC2-Instance-Connect.html)
	// in the Amazon EC2 User Guide.
	SendSSHPublicKey(ctx context.Context, params *ec2instanceconnect.SendSSHPublicKeyInput, optFns ...func(*ec2instanceconnect.Options)) (*ec2instanceconnect.SendSSHPublicKeyOutput, error)

	// Retrieve returns nil if it successfully retrieved the value.
	// Error is returned if the value were not obtainable, or empty.
	Retrieve(ctx context.Context) (aws.Credentials, error)
}

type defaultOpenTunnelEC2Client struct {
	*ec2.Client
	awsCredentialsProvider aws.CredentialsProvider
	ec2icClient            *ec2instanceconnect.Client
}

// SendSSHPublicKey pushes an SSH public key to the specified EC2 instance for use by the specified
// user. The key remains for 60 seconds. For more information, see Connect to your
// Linux instance using EC2 Instance Connect (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Connect-using-EC2-Instance-Connect.html)
// in the Amazon EC2 User Guide.
func (d defaultOpenTunnelEC2Client) SendSSHPublicKey(ctx context.Context, params *ec2instanceconnect.SendSSHPublicKeyInput, optFns ...func(*ec2instanceconnect.Options)) (*ec2instanceconnect.SendSSHPublicKeyOutput, error) {
	return d.ec2icClient.SendSSHPublicKey(ctx, params, optFns...)
}

// Retrieve returns nil if it successfully retrieved the value.
// Error is returned if the value were not obtainable, or empty.
func (d defaultOpenTunnelEC2Client) Retrieve(ctx context.Context) (aws.Credentials, error) {
	return d.awsCredentialsProvider.Retrieve(ctx)
}

// NewOpenTunnelEC2Client creates a OpenTunnelEC2Client using AWSClientRequest.
func NewOpenTunnelEC2Client(ctx context.Context, clientReq *AWSClientRequest) (OpenTunnelEC2Client, error) {
	ec2Client, err := newEC2Client(ctx, clientReq)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	ec2instanceconnectClient, err := newEC2InstanceConnectClient(ctx, clientReq)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	awsCredProvider, err := newAWSCredentialsProvider(ctx, clientReq)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &defaultOpenTunnelEC2Client{
		Client:                 ec2Client,
		awsCredentialsProvider: awsCredProvider,
		ec2icClient:            ec2instanceconnectClient,
	}, nil
}

// OpenTunnelEC2 creates a tunnel to an ec2 instance using its private IP.
// Ref:
// - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/connect-using-eice.html
// - https://github.com/aws/aws-cli/blob/f6c820e89d8b566ab54ab9d863754ec4b713fd6a/awscli/customizations/ec2instanceconnect/opentunnel.py
//
// High level archictecture:
// - create a new SSH Key SK1
// - send SK1 key using ec2instanceconnect.SendSSHPublicKey
// - open TCP listener to receive connections from Teleport Proxy
// - when a connection arrives C1, it connects to the websocket (EC2 Instance Connect Endpoint service), the websocket connects to the EC2 instance.
// - the proxy then talks SSH protocol to C1, which in turn pipes the tcp stream via websocket to EC2 Instance Connect Endpoint, which in turns pipes the stream to the EC2 instance.
// - the proxy sends the Public Key created in the first step in order to authenticate.
func OpenTunnelEC2(ctx context.Context, clt OpenTunnelEC2Client, req OpenTunnelEC2Request) (*OpenTunnelEC2Response, error) {
	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	sshSigner, err := sendSSHPublicKey(ctx, clt, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	eice, err := fetchEC2InstanceConnectEndpoint(ctx, clt, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	ec2Conn, err := dialEC2InstanceUsingEICE(ctx, dialEC2InstanceUsingEICERequest{
		credsProvider:    clt,
		awsRegion:        req.Region,
		endpointId:       *eice.InstanceConnectEndpointId,
		endpointHost:     *eice.DnsName,
		privateIPAddress: req.ec2PrivateHostname,
		remotePort:       req.ec2OpenSSHPort,
		customCA:         req.websocketCustomCA,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &OpenTunnelEC2Response{
		SSHSigner: sshSigner,
		Tunnel:    ec2Conn,
	}, nil
}

// fetchEC2InstanceConnectEndpoint returns an EC2InstanceConnectEndpoint for the given VPC and whose state is ready to use ("create-complete").
func fetchEC2InstanceConnectEndpoint(ctx context.Context, clt OpenTunnelEC2Client, req OpenTunnelEC2Request) (*ec2types.Ec2InstanceConnectEndpoint, error) {
	describe, err := clt.DescribeInstanceConnectEndpoints(ctx, &ec2.DescribeInstanceConnectEndpointsInput{
		Filters: []ec2types.Filter{
			{
				Name:   &filterEC2InstanceConnectEndpointVPCIDKey,
				Values: []string{req.VPCID},
			},
			{
				Name:   &filterEC2InstanceConnectEndpointStateKey,
				Values: []string{string(ec2types.Ec2InstanceConnectEndpointStateCreateComplete)},
			},
		},
	})
	if err != nil {
		return nil, trace.BadParameter("failed to list EC2 Instance Connect Endpoint for VPC %q (region=%q): %v", req.VPCID, req.Region, err)
	}

	if len(describe.InstanceConnectEndpoints) == 0 {
		return nil, trace.BadParameter("no EC2 Instance Connect Endpoint for VPC %q (region=%q), please create one", req.VPCID, req.Region)
	}

	return &describe.InstanceConnectEndpoints[0], nil
}

// dialEC2InstanceUsingEICERequest is a request to dial into an EC2 Instance Connect Endpoint.
type dialEC2InstanceUsingEICERequest struct {
	credsProvider    aws.CredentialsProvider
	awsRegion        string
	endpointId       string
	customCA         *x509.Certificate
	endpointHost     string
	privateIPAddress string
	remotePort       string
}

// dialEC2InstanceUsingEICE dials into an EC2 instance port using an EC2 Instance Connect Endpoint.
// Returns a net.Conn that transparently proxies the connection to the EC2 instance.
func dialEC2InstanceUsingEICE(ctx context.Context, req dialEC2InstanceUsingEICERequest) (net.Conn, error) {
	// There's no official documentation on how to connect to the EC2 Instance Connect Endpoint.
	// So, we had to rely on the awscli implementation, which you can find here:
	// https://github.com/aws/aws-cli/blob/f6c820e89d8b566ab54ab9d863754ec4b713fd6a/awscli/customizations/ec2instanceconnect/opentunnel.py
	//
	// The lack of documentation means this implementation is a risk, however, by following awscli implementation we are confident that
	// it will work for the foreseable future (aws will *probably* not break old awscli versions).
	q := url.Values{}
	q.Set("instanceConnectEndpointId", req.endpointId)
	q.Set("maxTunnelDuration", "3600") // 1 hour (max allowed)
	q.Set("privateIpAddress", req.privateIPAddress)
	q.Set("remotePort", req.remotePort)

	openTunnelURL := url.URL{
		Scheme:   "wss",
		Host:     req.endpointHost,
		Path:     "openTunnel",
		RawQuery: q.Encode(),
	}

	r, err := http.NewRequest(http.MethodGet, openTunnelURL.String(), nil)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	creds, err := req.credsProvider.Retrieve(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	s := signer.NewSigner()
	signed, _, err := s.PresignHTTP(ctx, creds, r, hashForGetRequests, "ec2-instance-connect", req.awsRegion, time.Now())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	websocketDialer := websocket.DefaultDialer

	// For testing purposes only. Adds the httpTestServer CA
	if req.customCA != nil {
		if !strings.HasPrefix(req.endpointHost, "127.0.0.1:") {
			return nil, trace.BadParameter("custom CA can only be used for testing and the websocket address must be localhost: %v", req.endpointHost)
		}
		websocketDialer.TLSClientConfig = &tls.Config{
			RootCAs: x509.NewCertPool(),
		}
		websocketDialer.TLSClientConfig.RootCAs.AddCert(req.customCA)
	}

	conn, resp, err := websocketDialer.DialContext(ctx, signed, http.Header{})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer resp.Body.Close()

	return &eicedConn{
		Conn: conn,
		r:    websocket.JoinMessages(conn, ""),
	}, nil
}

// eicedConn is a net.Conn implementation that reads from reader r and writes into a websocket.Conn
type eicedConn struct {
	*websocket.Conn
	r io.Reader
}

// Reads from the reader into b and returns the number of read bytes.
func (i *eicedConn) Read(b []byte) (n int, err error) {
	return i.r.Read(b)
}

// Write writes into the websocket connection the contents of b.
// Returns how many bytes were written.
func (i *eicedConn) Write(b []byte) (int, error) {
	return len(b), i.Conn.WriteMessage(websocket.BinaryMessage, b)
}

// SetDeadline sets the websocket read and write deadline.
func (i *eicedConn) SetDeadline(t time.Time) error {
	i.SetReadDeadline(t)
	i.SetWriteDeadline(t)
	return nil
}
