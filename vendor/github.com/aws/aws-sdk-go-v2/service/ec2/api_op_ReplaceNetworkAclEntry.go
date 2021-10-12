// Code generated by smithy-go-codegen DO NOT EDIT.

package ec2

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Replaces an entry (rule) in a network ACL. For more information, see Network
// ACLs (https://docs.aws.amazon.com/vpc/latest/userguide/VPC_ACLs.html) in the
// Amazon Virtual Private Cloud User Guide.
func (c *Client) ReplaceNetworkAclEntry(ctx context.Context, params *ReplaceNetworkAclEntryInput, optFns ...func(*Options)) (*ReplaceNetworkAclEntryOutput, error) {
	if params == nil {
		params = &ReplaceNetworkAclEntryInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "ReplaceNetworkAclEntry", params, optFns, c.addOperationReplaceNetworkAclEntryMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*ReplaceNetworkAclEntryOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type ReplaceNetworkAclEntryInput struct {

	// Indicates whether to replace the egress rule. Default: If no value is specified,
	// we replace the ingress rule.
	//
	// This member is required.
	Egress *bool

	// The ID of the ACL.
	//
	// This member is required.
	NetworkAclId *string

	// The protocol number. A value of "-1" means all protocols. If you specify "-1" or
	// a protocol number other than "6" (TCP), "17" (UDP), or "1" (ICMP), traffic on
	// all ports is allowed, regardless of any ports or ICMP types or codes that you
	// specify. If you specify protocol "58" (ICMPv6) and specify an IPv4 CIDR block,
	// traffic for all ICMP types and codes allowed, regardless of any that you
	// specify. If you specify protocol "58" (ICMPv6) and specify an IPv6 CIDR block,
	// you must specify an ICMP type and code.
	//
	// This member is required.
	Protocol *string

	// Indicates whether to allow or deny the traffic that matches the rule.
	//
	// This member is required.
	RuleAction types.RuleAction

	// The rule number of the entry to replace.
	//
	// This member is required.
	RuleNumber *int32

	// The IPv4 network range to allow or deny, in CIDR notation (for example
	// 172.16.0.0/24).
	CidrBlock *string

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation. Otherwise, it is
	// UnauthorizedOperation.
	DryRun *bool

	// ICMP protocol: The ICMP or ICMPv6 type and code. Required if specifying protocol
	// 1 (ICMP) or protocol 58 (ICMPv6) with an IPv6 CIDR block.
	IcmpTypeCode *types.IcmpTypeCode

	// The IPv6 network range to allow or deny, in CIDR notation (for example
	// 2001:bd8:1234:1a00::/64).
	Ipv6CidrBlock *string

	// TCP or UDP protocols: The range of ports the rule applies to. Required if
	// specifying protocol 6 (TCP) or 17 (UDP).
	PortRange *types.PortRange

	noSmithyDocumentSerde
}

type ReplaceNetworkAclEntryOutput struct {
	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationReplaceNetworkAclEntryMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpReplaceNetworkAclEntry{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpReplaceNetworkAclEntry{}, middleware.After)
	if err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddClientRequestIDMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddComputeContentLengthMiddleware(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = v4.AddComputePayloadSHA256Middleware(stack); err != nil {
		return err
	}
	if err = addRetryMiddlewares(stack, options); err != nil {
		return err
	}
	if err = addHTTPSignerV4Middleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = awsmiddleware.AddRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addClientUserAgent(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addOpReplaceNetworkAclEntryValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opReplaceNetworkAclEntry(options.Region), middleware.Before); err != nil {
		return err
	}
	if err = addRequestIDRetrieverMiddleware(stack); err != nil {
		return err
	}
	if err = addResponseErrorMiddleware(stack); err != nil {
		return err
	}
	if err = addRequestResponseLogging(stack, options); err != nil {
		return err
	}
	return nil
}

func newServiceMetadataMiddleware_opReplaceNetworkAclEntry(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "ReplaceNetworkAclEntry",
	}
}
