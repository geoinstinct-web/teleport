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

// Describes your IAM instance profile associations.
func (c *Client) DescribeIamInstanceProfileAssociations(ctx context.Context, params *DescribeIamInstanceProfileAssociationsInput, optFns ...func(*Options)) (*DescribeIamInstanceProfileAssociationsOutput, error) {
	if params == nil {
		params = &DescribeIamInstanceProfileAssociationsInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DescribeIamInstanceProfileAssociations", params, optFns, c.addOperationDescribeIamInstanceProfileAssociationsMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DescribeIamInstanceProfileAssociationsOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type DescribeIamInstanceProfileAssociationsInput struct {

	// The IAM instance profile associations.
	AssociationIds []string

	// The filters.
	//
	// * instance-id - The ID of the instance.
	//
	// * state - The state of
	// the association (associating | associated | disassociating).
	Filters []types.Filter

	// The maximum number of results to return in a single call. To retrieve the
	// remaining results, make another call with the returned NextToken value.
	MaxResults *int32

	// The token to request the next page of results.
	NextToken *string

	noSmithyDocumentSerde
}

type DescribeIamInstanceProfileAssociationsOutput struct {

	// Information about the IAM instance profile associations.
	IamInstanceProfileAssociations []types.IamInstanceProfileAssociation

	// The token to use to retrieve the next page of results. This value is null when
	// there are no more results to return.
	NextToken *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationDescribeIamInstanceProfileAssociationsMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpDescribeIamInstanceProfileAssociations{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpDescribeIamInstanceProfileAssociations{}, middleware.After)
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
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDescribeIamInstanceProfileAssociations(options.Region), middleware.Before); err != nil {
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

// DescribeIamInstanceProfileAssociationsAPIClient is a client that implements the
// DescribeIamInstanceProfileAssociations operation.
type DescribeIamInstanceProfileAssociationsAPIClient interface {
	DescribeIamInstanceProfileAssociations(context.Context, *DescribeIamInstanceProfileAssociationsInput, ...func(*Options)) (*DescribeIamInstanceProfileAssociationsOutput, error)
}

var _ DescribeIamInstanceProfileAssociationsAPIClient = (*Client)(nil)

// DescribeIamInstanceProfileAssociationsPaginatorOptions is the paginator options
// for DescribeIamInstanceProfileAssociations
type DescribeIamInstanceProfileAssociationsPaginatorOptions struct {
	// The maximum number of results to return in a single call. To retrieve the
	// remaining results, make another call with the returned NextToken value.
	Limit int32

	// Set to true if pagination should stop if the service returns a pagination token
	// that matches the most recent token provided to the service.
	StopOnDuplicateToken bool
}

// DescribeIamInstanceProfileAssociationsPaginator is a paginator for
// DescribeIamInstanceProfileAssociations
type DescribeIamInstanceProfileAssociationsPaginator struct {
	options   DescribeIamInstanceProfileAssociationsPaginatorOptions
	client    DescribeIamInstanceProfileAssociationsAPIClient
	params    *DescribeIamInstanceProfileAssociationsInput
	nextToken *string
	firstPage bool
}

// NewDescribeIamInstanceProfileAssociationsPaginator returns a new
// DescribeIamInstanceProfileAssociationsPaginator
func NewDescribeIamInstanceProfileAssociationsPaginator(client DescribeIamInstanceProfileAssociationsAPIClient, params *DescribeIamInstanceProfileAssociationsInput, optFns ...func(*DescribeIamInstanceProfileAssociationsPaginatorOptions)) *DescribeIamInstanceProfileAssociationsPaginator {
	if params == nil {
		params = &DescribeIamInstanceProfileAssociationsInput{}
	}

	options := DescribeIamInstanceProfileAssociationsPaginatorOptions{}
	if params.MaxResults != nil {
		options.Limit = *params.MaxResults
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &DescribeIamInstanceProfileAssociationsPaginator{
		options:   options,
		client:    client,
		params:    params,
		firstPage: true,
	}
}

// HasMorePages returns a boolean indicating whether more pages are available
func (p *DescribeIamInstanceProfileAssociationsPaginator) HasMorePages() bool {
	return p.firstPage || p.nextToken != nil
}

// NextPage retrieves the next DescribeIamInstanceProfileAssociations page.
func (p *DescribeIamInstanceProfileAssociationsPaginator) NextPage(ctx context.Context, optFns ...func(*Options)) (*DescribeIamInstanceProfileAssociationsOutput, error) {
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

	result, err := p.client.DescribeIamInstanceProfileAssociations(ctx, &params, optFns...)
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

func newServiceMetadataMiddleware_opDescribeIamInstanceProfileAssociations(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "DescribeIamInstanceProfileAssociations",
	}
}
