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

// Describes active client connections and connections that have been terminated
// within the last 60 minutes for the specified Client VPN endpoint.
func (c *Client) DescribeClientVpnConnections(ctx context.Context, params *DescribeClientVpnConnectionsInput, optFns ...func(*Options)) (*DescribeClientVpnConnectionsOutput, error) {
	if params == nil {
		params = &DescribeClientVpnConnectionsInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DescribeClientVpnConnections", params, optFns, c.addOperationDescribeClientVpnConnectionsMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DescribeClientVpnConnectionsOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type DescribeClientVpnConnectionsInput struct {

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
	// connection-id - The ID of the connection.
	//
	// * username - For Active Directory
	// client authentication, the user name of the client who established the client
	// connection.
	Filters []types.Filter

	// The maximum number of results to return for the request in a single page. The
	// remaining results can be seen by sending another request with the nextToken
	// value.
	MaxResults *int32

	// The token to retrieve the next page of results.
	NextToken *string

	noSmithyDocumentSerde
}

type DescribeClientVpnConnectionsOutput struct {

	// Information about the active and terminated client connections.
	Connections []types.ClientVpnConnection

	// The token to use to retrieve the next page of results. This value is null when
	// there are no more results to return.
	NextToken *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationDescribeClientVpnConnectionsMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpDescribeClientVpnConnections{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpDescribeClientVpnConnections{}, middleware.After)
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
	if err = addOpDescribeClientVpnConnectionsValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDescribeClientVpnConnections(options.Region), middleware.Before); err != nil {
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

// DescribeClientVpnConnectionsAPIClient is a client that implements the
// DescribeClientVpnConnections operation.
type DescribeClientVpnConnectionsAPIClient interface {
	DescribeClientVpnConnections(context.Context, *DescribeClientVpnConnectionsInput, ...func(*Options)) (*DescribeClientVpnConnectionsOutput, error)
}

var _ DescribeClientVpnConnectionsAPIClient = (*Client)(nil)

// DescribeClientVpnConnectionsPaginatorOptions is the paginator options for
// DescribeClientVpnConnections
type DescribeClientVpnConnectionsPaginatorOptions struct {
	// The maximum number of results to return for the request in a single page. The
	// remaining results can be seen by sending another request with the nextToken
	// value.
	Limit int32

	// Set to true if pagination should stop if the service returns a pagination token
	// that matches the most recent token provided to the service.
	StopOnDuplicateToken bool
}

// DescribeClientVpnConnectionsPaginator is a paginator for
// DescribeClientVpnConnections
type DescribeClientVpnConnectionsPaginator struct {
	options   DescribeClientVpnConnectionsPaginatorOptions
	client    DescribeClientVpnConnectionsAPIClient
	params    *DescribeClientVpnConnectionsInput
	nextToken *string
	firstPage bool
}

// NewDescribeClientVpnConnectionsPaginator returns a new
// DescribeClientVpnConnectionsPaginator
func NewDescribeClientVpnConnectionsPaginator(client DescribeClientVpnConnectionsAPIClient, params *DescribeClientVpnConnectionsInput, optFns ...func(*DescribeClientVpnConnectionsPaginatorOptions)) *DescribeClientVpnConnectionsPaginator {
	if params == nil {
		params = &DescribeClientVpnConnectionsInput{}
	}

	options := DescribeClientVpnConnectionsPaginatorOptions{}
	if params.MaxResults != nil {
		options.Limit = *params.MaxResults
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &DescribeClientVpnConnectionsPaginator{
		options:   options,
		client:    client,
		params:    params,
		firstPage: true,
	}
}

// HasMorePages returns a boolean indicating whether more pages are available
func (p *DescribeClientVpnConnectionsPaginator) HasMorePages() bool {
	return p.firstPage || p.nextToken != nil
}

// NextPage retrieves the next DescribeClientVpnConnections page.
func (p *DescribeClientVpnConnectionsPaginator) NextPage(ctx context.Context, optFns ...func(*Options)) (*DescribeClientVpnConnectionsOutput, error) {
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

	result, err := p.client.DescribeClientVpnConnections(ctx, &params, optFns...)
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

func newServiceMetadataMiddleware_opDescribeClientVpnConnections(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "DescribeClientVpnConnections",
	}
}
