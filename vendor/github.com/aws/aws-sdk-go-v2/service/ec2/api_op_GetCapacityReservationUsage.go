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

// Gets usage information about a Capacity Reservation. If the Capacity Reservation
// is shared, it shows usage information for the Capacity Reservation owner and
// each Amazon Web Services account that is currently using the shared capacity. If
// the Capacity Reservation is not shared, it shows only the Capacity Reservation
// owner's usage.
func (c *Client) GetCapacityReservationUsage(ctx context.Context, params *GetCapacityReservationUsageInput, optFns ...func(*Options)) (*GetCapacityReservationUsageOutput, error) {
	if params == nil {
		params = &GetCapacityReservationUsageInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "GetCapacityReservationUsage", params, optFns, c.addOperationGetCapacityReservationUsageMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*GetCapacityReservationUsageOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type GetCapacityReservationUsageInput struct {

	// The ID of the Capacity Reservation.
	//
	// This member is required.
	CapacityReservationId *string

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation. Otherwise, it is
	// UnauthorizedOperation.
	DryRun *bool

	// The maximum number of results to return for the request in a single page. The
	// remaining results can be seen by sending another request with the returned
	// nextToken value. This value can be between 5 and 500. If maxResults is given a
	// larger value than 500, you receive an error. Valid range: Minimum value of 1.
	// Maximum value of 1000.
	MaxResults *int32

	// The token to use to retrieve the next page of results.
	NextToken *string

	noSmithyDocumentSerde
}

type GetCapacityReservationUsageOutput struct {

	// The remaining capacity. Indicates the number of instances that can be launched
	// in the Capacity Reservation.
	AvailableInstanceCount *int32

	// The ID of the Capacity Reservation.
	CapacityReservationId *string

	// The type of instance for which the Capacity Reservation reserves capacity.
	InstanceType *string

	// Information about the Capacity Reservation usage.
	InstanceUsages []types.InstanceUsage

	// The token to use to retrieve the next page of results. This value is null when
	// there are no more results to return.
	NextToken *string

	// The current state of the Capacity Reservation. A Capacity Reservation can be in
	// one of the following states:
	//
	// * active - The Capacity Reservation is active and
	// the capacity is available for your use.
	//
	// * expired - The Capacity Reservation
	// expired automatically at the date and time specified in your request. The
	// reserved capacity is no longer available for your use.
	//
	// * cancelled - The
	// Capacity Reservation was cancelled. The reserved capacity is no longer available
	// for your use.
	//
	// * pending - The Capacity Reservation request was successful but
	// the capacity provisioning is still pending.
	//
	// * failed - The Capacity Reservation
	// request has failed. A request might fail due to invalid request parameters,
	// capacity constraints, or instance limit constraints. Failed requests are
	// retained for 60 minutes.
	State types.CapacityReservationState

	// The number of instances for which the Capacity Reservation reserves capacity.
	TotalInstanceCount *int32

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationGetCapacityReservationUsageMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpGetCapacityReservationUsage{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpGetCapacityReservationUsage{}, middleware.After)
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
	if err = addOpGetCapacityReservationUsageValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opGetCapacityReservationUsage(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opGetCapacityReservationUsage(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "GetCapacityReservationUsage",
	}
}
