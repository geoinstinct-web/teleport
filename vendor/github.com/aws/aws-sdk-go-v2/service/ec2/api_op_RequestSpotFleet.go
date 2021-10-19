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

// Creates a Spot Fleet request. The Spot Fleet request specifies the total target
// capacity and the On-Demand target capacity. Amazon EC2 calculates the difference
// between the total capacity and On-Demand capacity, and launches the difference
// as Spot capacity. You can submit a single request that includes multiple launch
// specifications that vary by instance type, AMI, Availability Zone, or subnet. By
// default, the Spot Fleet requests Spot Instances in the Spot Instance pool where
// the price per unit is the lowest. Each launch specification can include its own
// instance weighting that reflects the value of the instance type to your
// application workload. Alternatively, you can specify that the Spot Fleet
// distribute the target capacity across the Spot pools included in its launch
// specifications. By ensuring that the Spot Instances in your Spot Fleet are in
// different Spot pools, you can improve the availability of your fleet. You can
// specify tags for the Spot Fleet request and instances launched by the fleet. You
// cannot tag other resource types in a Spot Fleet request because only the
// spot-fleet-request and instance resource types are supported. For more
// information, see Spot Fleet requests
// (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-fleet-requests.html)
// in the Amazon EC2 User Guide for Linux Instances.
func (c *Client) RequestSpotFleet(ctx context.Context, params *RequestSpotFleetInput, optFns ...func(*Options)) (*RequestSpotFleetOutput, error) {
	if params == nil {
		params = &RequestSpotFleetInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "RequestSpotFleet", params, optFns, c.addOperationRequestSpotFleetMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*RequestSpotFleetOutput)
	out.ResultMetadata = metadata
	return out, nil
}

// Contains the parameters for RequestSpotFleet.
type RequestSpotFleetInput struct {

	// The configuration for the Spot Fleet request.
	//
	// This member is required.
	SpotFleetRequestConfig *types.SpotFleetRequestConfigData

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation. Otherwise, it is
	// UnauthorizedOperation.
	DryRun *bool

	noSmithyDocumentSerde
}

// Contains the output of RequestSpotFleet.
type RequestSpotFleetOutput struct {

	// The ID of the Spot Fleet request.
	SpotFleetRequestId *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationRequestSpotFleetMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpRequestSpotFleet{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpRequestSpotFleet{}, middleware.After)
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
	if err = addOpRequestSpotFleetValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opRequestSpotFleet(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opRequestSpotFleet(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "RequestSpotFleet",
	}
}
