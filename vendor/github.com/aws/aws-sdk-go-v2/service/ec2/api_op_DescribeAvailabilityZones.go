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

// Describes the Availability Zones, Local Zones, and Wavelength Zones that are
// available to you. If there is an event impacting a zone, you can use this
// request to view the state and any provided messages for that zone. For more
// information about Availability Zones, Local Zones, and Wavelength Zones, see
// Regions, Zones and Outposts
// (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html)
// in the Amazon Elastic Compute Cloud User Guide.
func (c *Client) DescribeAvailabilityZones(ctx context.Context, params *DescribeAvailabilityZonesInput, optFns ...func(*Options)) (*DescribeAvailabilityZonesOutput, error) {
	if params == nil {
		params = &DescribeAvailabilityZonesInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DescribeAvailabilityZones", params, optFns, c.addOperationDescribeAvailabilityZonesMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DescribeAvailabilityZonesOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type DescribeAvailabilityZonesInput struct {

	// Include all Availability Zones, Local Zones, and Wavelength Zones regardless of
	// your opt-in status. If you do not use this parameter, the results include only
	// the zones for the Regions where you have chosen the option to opt in.
	AllAvailabilityZones *bool

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation. Otherwise, it is
	// UnauthorizedOperation.
	DryRun *bool

	// The filters.
	//
	// * group-name - For Availability Zones, use the Region name. For
	// Local Zones, use the name of the group associated with the Local Zone (for
	// example, us-west-2-lax-1) For Wavelength Zones, use the name of the group
	// associated with the Wavelength Zone (for example, us-east-1-wl1-bos-wlz-1).
	//
	// *
	// message - The Zone message.
	//
	// * opt-in-status - The opt-in status (opted-in, and
	// not-opted-in | opt-in-not-required).
	//
	// * parent-zoneID - The ID of the zone that
	// handles some of the Local Zone and Wavelength Zone control plane operations,
	// such as API calls.
	//
	// * parent-zoneName - The ID of the zone that handles some of
	// the Local Zone and Wavelength Zone control plane operations, such as API
	// calls.
	//
	// * region-name - The name of the Region for the Zone (for example,
	// us-east-1).
	//
	// * state - The state of the Availability Zone, the Local Zone, or
	// the Wavelength Zone (available | information | impaired | unavailable).
	//
	// *
	// zone-id - The ID of the Availability Zone (for example, use1-az1), the Local
	// Zone (for example, usw2-lax1-az1), or the Wavelength Zone (for example,
	// us-east-1-wl1-bos-wlz-1).
	//
	// * zone-type - The type of zone, for example,
	// local-zone.
	//
	// * zone-name - The name of the Availability Zone (for example,
	// us-east-1a), the Local Zone (for example, us-west-2-lax-1a), or the Wavelength
	// Zone (for example, us-east-1-wl1-bos-wlz-1).
	//
	// * zone-type - The type of zone,
	// for example, local-zone.
	Filters []types.Filter

	// The IDs of the Availability Zones, Local Zones, and Wavelength Zones.
	ZoneIds []string

	// The names of the Availability Zones, Local Zones, and Wavelength Zones.
	ZoneNames []string

	noSmithyDocumentSerde
}

type DescribeAvailabilityZonesOutput struct {

	// Information about the Availability Zones, Local Zones, and Wavelength Zones.
	AvailabilityZones []types.AvailabilityZone

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationDescribeAvailabilityZonesMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpDescribeAvailabilityZones{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpDescribeAvailabilityZones{}, middleware.After)
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
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDescribeAvailabilityZones(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opDescribeAvailabilityZones(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "DescribeAvailabilityZones",
	}
}
