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

// Modifies a subnet attribute. You can only modify one attribute at a time.
func (c *Client) ModifySubnetAttribute(ctx context.Context, params *ModifySubnetAttributeInput, optFns ...func(*Options)) (*ModifySubnetAttributeOutput, error) {
	if params == nil {
		params = &ModifySubnetAttributeInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "ModifySubnetAttribute", params, optFns, c.addOperationModifySubnetAttributeMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*ModifySubnetAttributeOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type ModifySubnetAttributeInput struct {

	// The ID of the subnet.
	//
	// This member is required.
	SubnetId *string

	// Specify true to indicate that network interfaces created in the specified subnet
	// should be assigned an IPv6 address. This includes a network interface that's
	// created when launching an instance into the subnet (the instance therefore
	// receives an IPv6 address). If you enable the IPv6 addressing feature for your
	// subnet, your network interface or instance only receives an IPv6 address if it's
	// created using version 2016-11-15 or later of the Amazon EC2 API.
	AssignIpv6AddressOnCreation *types.AttributeBooleanValue

	// The customer-owned IPv4 address pool associated with the subnet. You must set
	// this value when you specify true for MapCustomerOwnedIpOnLaunch.
	CustomerOwnedIpv4Pool *string

	// Specify true to indicate that network interfaces attached to instances created
	// in the specified subnet should be assigned a customer-owned IPv4 address. When
	// this value is true, you must specify the customer-owned IP pool using
	// CustomerOwnedIpv4Pool.
	MapCustomerOwnedIpOnLaunch *types.AttributeBooleanValue

	// Specify true to indicate that network interfaces attached to instances created
	// in the specified subnet should be assigned a public IPv4 address.
	MapPublicIpOnLaunch *types.AttributeBooleanValue

	noSmithyDocumentSerde
}

type ModifySubnetAttributeOutput struct {
	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationModifySubnetAttributeMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpModifySubnetAttribute{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpModifySubnetAttribute{}, middleware.After)
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
	if err = addOpModifySubnetAttributeValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opModifySubnetAttribute(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opModifySubnetAttribute(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "ModifySubnetAttribute",
	}
}
