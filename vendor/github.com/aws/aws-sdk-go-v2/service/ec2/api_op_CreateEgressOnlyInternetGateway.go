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

// [IPv6 only] Creates an egress-only internet gateway for your VPC. An egress-only
// internet gateway is used to enable outbound communication over IPv6 from
// instances in your VPC to the internet, and prevents hosts outside of your VPC
// from initiating an IPv6 connection with your instance.
func (c *Client) CreateEgressOnlyInternetGateway(ctx context.Context, params *CreateEgressOnlyInternetGatewayInput, optFns ...func(*Options)) (*CreateEgressOnlyInternetGatewayOutput, error) {
	if params == nil {
		params = &CreateEgressOnlyInternetGatewayInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "CreateEgressOnlyInternetGateway", params, optFns, c.addOperationCreateEgressOnlyInternetGatewayMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*CreateEgressOnlyInternetGatewayOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type CreateEgressOnlyInternetGatewayInput struct {

	// The ID of the VPC for which to create the egress-only internet gateway.
	//
	// This member is required.
	VpcId *string

	// Unique, case-sensitive identifier that you provide to ensure the idempotency of
	// the request. For more information, see How to ensure idempotency
	// (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Run_Instance_Idempotency.html).
	ClientToken *string

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation. Otherwise, it is
	// UnauthorizedOperation.
	DryRun *bool

	// The tags to assign to the egress-only internet gateway.
	TagSpecifications []types.TagSpecification

	noSmithyDocumentSerde
}

type CreateEgressOnlyInternetGatewayOutput struct {

	// Unique, case-sensitive identifier that you provide to ensure the idempotency of
	// the request.
	ClientToken *string

	// Information about the egress-only internet gateway.
	EgressOnlyInternetGateway *types.EgressOnlyInternetGateway

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationCreateEgressOnlyInternetGatewayMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpCreateEgressOnlyInternetGateway{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpCreateEgressOnlyInternetGateway{}, middleware.After)
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
	if err = addOpCreateEgressOnlyInternetGatewayValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opCreateEgressOnlyInternetGateway(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opCreateEgressOnlyInternetGateway(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "CreateEgressOnlyInternetGateway",
	}
}
