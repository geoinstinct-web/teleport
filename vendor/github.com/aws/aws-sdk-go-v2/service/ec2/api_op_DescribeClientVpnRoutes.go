// Code generated by smithy-go-codegen DO NOT EDIT.

package ec2

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Describes the routes for the specified Client VPN endpoint.
func (c *Client) DescribeClientVpnRoutes(ctx context.Context, params *DescribeClientVpnRoutesInput, optFns ...func(*Options)) (*DescribeClientVpnRoutesOutput, error) {
	if params == nil {
		params = &DescribeClientVpnRoutesInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DescribeClientVpnRoutes", params, optFns, c.addOperationDescribeClientVpnRoutesMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DescribeClientVpnRoutesOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type DescribeClientVpnRoutesInput struct {

	// The ID of the Client VPN endpoint.
	//
	// This member is required.
	ClientVpnEndpointId *string

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation. Otherwise, it is
	// UnauthorizedOperation.
	DryRun *bool

	// One or more filters. Filter names and values are case-sensitive.
	//
	// *
	// destination-cidr - The CIDR of the route destination.
	//
	// * origin - How the route
	// was associated with the Client VPN endpoint (associate | add-route).
	//
	// *
	// target-subnet - The ID of the subnet through which traffic is routed.
	Filters []types.Filter

	// The maximum number of results to return for the request in a single page. The
	// remaining results can be seen by sending another request with the nextToken
	// value.
	MaxResults *int32

	// The token to retrieve the next page of results.
	NextToken *string

	noSmithyDocumentSerde
}

type DescribeClientVpnRoutesOutput struct {

	// The token to use to retrieve the next page of results. This value is null when
	// there are no more results to return.
	NextToken *string

	// Information about the Client VPN endpoint routes.
	Routes []types.ClientVpnRoute

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationDescribeClientVpnRoutesMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpDescribeClientVpnRoutes{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpDescribeClientVpnRoutes{}, middleware.After)
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
	if err = addOpDescribeClientVpnRoutesValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDescribeClientVpnRoutes(options.Region), middleware.Before); err != nil {
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

// DescribeClientVpnRoutesAPIClient is a client that implements the
// DescribeClientVpnRoutes operation.
type DescribeClientVpnRoutesAPIClient interface {
	DescribeClientVpnRoutes(context.Context, *DescribeClientVpnRoutesInput, ...func(*Options)) (*DescribeClientVpnRoutesOutput, error)
}

var _ DescribeClientVpnRoutesAPIClient = (*Client)(nil)

// DescribeClientVpnRoutesPaginatorOptions is the paginator options for
// DescribeClientVpnRoutes
type DescribeClientVpnRoutesPaginatorOptions struct {
	// The maximum number of results to return for the request in a single page. The
	// remaining results can be seen by sending another request with the nextToken
	// value.
	Limit int32

	// Set to true if pagination should stop if the service returns a pagination token
	// that matches the most recent token provided to the service.
	StopOnDuplicateToken bool
}

// DescribeClientVpnRoutesPaginator is a paginator for DescribeClientVpnRoutes
type DescribeClientVpnRoutesPaginator struct {
	options   DescribeClientVpnRoutesPaginatorOptions
	client    DescribeClientVpnRoutesAPIClient
	params    *DescribeClientVpnRoutesInput
	nextToken *string
	firstPage bool
}

// NewDescribeClientVpnRoutesPaginator returns a new
// DescribeClientVpnRoutesPaginator
func NewDescribeClientVpnRoutesPaginator(client DescribeClientVpnRoutesAPIClient, params *DescribeClientVpnRoutesInput, optFns ...func(*DescribeClientVpnRoutesPaginatorOptions)) *DescribeClientVpnRoutesPaginator {
	if params == nil {
		params = &DescribeClientVpnRoutesInput{}
	}

	options := DescribeClientVpnRoutesPaginatorOptions{}
	if params.MaxResults != nil {
		options.Limit = *params.MaxResults
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &DescribeClientVpnRoutesPaginator{
		options:   options,
		client:    client,
		params:    params,
		firstPage: true,
	}
}

// HasMorePages returns a boolean indicating whether more pages are available
func (p *DescribeClientVpnRoutesPaginator) HasMorePages() bool {
	return p.firstPage || p.nextToken != nil
}

// NextPage retrieves the next DescribeClientVpnRoutes page.
func (p *DescribeClientVpnRoutesPaginator) NextPage(ctx context.Context, optFns ...func(*Options)) (*DescribeClientVpnRoutesOutput, error) {
	if !p.HasMorePages() {
		return nil, fmt.Errorf("no more pages available")
	}

	params := *p.params
	params.NextToken = p.nextToken

	var limit *int32
	if p.options.Limit > 0 {
		limit = &p.options.Limit
	}
	params.MaxResults = limit

	result, err := p.client.DescribeClientVpnRoutes(ctx, &params, optFns...)
	if err != nil {
		return nil, err
	}
	p.firstPage = false

	prevToken := p.nextToken
	p.nextToken = result.NextToken

	if p.options.StopOnDuplicateToken && prevToken != nil && p.nextToken != nil && *prevToken == *p.nextToken {
		p.nextToken = nil
	}

	return result, nil
}

func newServiceMetadataMiddleware_opDescribeClientVpnRoutes(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "DescribeClientVpnRoutes",
	}
}
