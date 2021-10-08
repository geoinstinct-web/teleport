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

// Gets information about the associations for the transit gateway multicast
// domain.
func (c *Client) GetTransitGatewayMulticastDomainAssociations(ctx context.Context, params *GetTransitGatewayMulticastDomainAssociationsInput, optFns ...func(*Options)) (*GetTransitGatewayMulticastDomainAssociationsOutput, error) {
	if params == nil {
		params = &GetTransitGatewayMulticastDomainAssociationsInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "GetTransitGatewayMulticastDomainAssociations", params, optFns, c.addOperationGetTransitGatewayMulticastDomainAssociationsMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*GetTransitGatewayMulticastDomainAssociationsOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type GetTransitGatewayMulticastDomainAssociationsInput struct {

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation. Otherwise, it is
	// UnauthorizedOperation.
	DryRun *bool

	// One or more filters. The possible values are:
	//
	// * resource-id - The ID of the
	// resource.
	//
	// * resource-type - The type of resource. The valid value is: vpc.
	//
	// *
	// state - The state of the subnet association. Valid values are associated |
	// associating | disassociated | disassociating.
	//
	// * subnet-id - The ID of the
	// subnet.
	//
	// * transit-gateway-attachment-id - The id of the transit gateway
	// attachment.
	Filters []types.Filter

	// The maximum number of results to return with a single call. To retrieve the
	// remaining results, make another call with the returned nextToken value.
	MaxResults *int32

	// The token for the next page of results.
	NextToken *string

	// The ID of the transit gateway multicast domain.
	TransitGatewayMulticastDomainId *string

	noSmithyDocumentSerde
}

type GetTransitGatewayMulticastDomainAssociationsOutput struct {

	// Information about the multicast domain associations.
	MulticastDomainAssociations []types.TransitGatewayMulticastDomainAssociation

	// The token to use to retrieve the next page of results. This value is null when
	// there are no more results to return.
	NextToken *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationGetTransitGatewayMulticastDomainAssociationsMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpGetTransitGatewayMulticastDomainAssociations{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpGetTransitGatewayMulticastDomainAssociations{}, middleware.After)
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
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opGetTransitGatewayMulticastDomainAssociations(options.Region), middleware.Before); err != nil {
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

// GetTransitGatewayMulticastDomainAssociationsAPIClient is a client that
// implements the GetTransitGatewayMulticastDomainAssociations operation.
type GetTransitGatewayMulticastDomainAssociationsAPIClient interface {
	GetTransitGatewayMulticastDomainAssociations(context.Context, *GetTransitGatewayMulticastDomainAssociationsInput, ...func(*Options)) (*GetTransitGatewayMulticastDomainAssociationsOutput, error)
}

var _ GetTransitGatewayMulticastDomainAssociationsAPIClient = (*Client)(nil)

// GetTransitGatewayMulticastDomainAssociationsPaginatorOptions is the paginator
// options for GetTransitGatewayMulticastDomainAssociations
type GetTransitGatewayMulticastDomainAssociationsPaginatorOptions struct {
	// The maximum number of results to return with a single call. To retrieve the
	// remaining results, make another call with the returned nextToken value.
	Limit int32

	// Set to true if pagination should stop if the service returns a pagination token
	// that matches the most recent token provided to the service.
	StopOnDuplicateToken bool
}

// GetTransitGatewayMulticastDomainAssociationsPaginator is a paginator for
// GetTransitGatewayMulticastDomainAssociations
type GetTransitGatewayMulticastDomainAssociationsPaginator struct {
	options   GetTransitGatewayMulticastDomainAssociationsPaginatorOptions
	client    GetTransitGatewayMulticastDomainAssociationsAPIClient
	params    *GetTransitGatewayMulticastDomainAssociationsInput
	nextToken *string
	firstPage bool
}

// NewGetTransitGatewayMulticastDomainAssociationsPaginator returns a new
// GetTransitGatewayMulticastDomainAssociationsPaginator
func NewGetTransitGatewayMulticastDomainAssociationsPaginator(client GetTransitGatewayMulticastDomainAssociationsAPIClient, params *GetTransitGatewayMulticastDomainAssociationsInput, optFns ...func(*GetTransitGatewayMulticastDomainAssociationsPaginatorOptions)) *GetTransitGatewayMulticastDomainAssociationsPaginator {
	if params == nil {
		params = &GetTransitGatewayMulticastDomainAssociationsInput{}
	}

	options := GetTransitGatewayMulticastDomainAssociationsPaginatorOptions{}
	if params.MaxResults != nil {
		options.Limit = *params.MaxResults
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &GetTransitGatewayMulticastDomainAssociationsPaginator{
		options:   options,
		client:    client,
		params:    params,
		firstPage: true,
	}
}

// HasMorePages returns a boolean indicating whether more pages are available
func (p *GetTransitGatewayMulticastDomainAssociationsPaginator) HasMorePages() bool {
	return p.firstPage || p.nextToken != nil
}

// NextPage retrieves the next GetTransitGatewayMulticastDomainAssociations page.
func (p *GetTransitGatewayMulticastDomainAssociationsPaginator) NextPage(ctx context.Context, optFns ...func(*Options)) (*GetTransitGatewayMulticastDomainAssociationsOutput, error) {
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

	result, err := p.client.GetTransitGatewayMulticastDomainAssociations(ctx, &params, optFns...)
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

func newServiceMetadataMiddleware_opGetTransitGatewayMulticastDomainAssociations(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "GetTransitGatewayMulticastDomainAssociations",
	}
}
