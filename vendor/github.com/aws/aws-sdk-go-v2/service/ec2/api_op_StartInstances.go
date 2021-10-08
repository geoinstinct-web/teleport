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

// Starts an Amazon EBS-backed instance that you've previously stopped. Instances
// that use Amazon EBS volumes as their root devices can be quickly stopped and
// started. When an instance is stopped, the compute resources are released and you
// are not billed for instance usage. However, your root partition Amazon EBS
// volume remains and continues to persist your data, and you are charged for
// Amazon EBS volume usage. You can restart your instance at any time. Every time
// you start your instance, Amazon EC2 charges a one-minute minimum for instance
// usage, and thereafter charges per second for instance usage. Before stopping an
// instance, make sure it is in a state from which it can be restarted. Stopping an
// instance does not preserve data stored in RAM. Performing this operation on an
// instance that uses an instance store as its root device returns an error. For
// more information, see Stopping instances
// (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Stop_Start.html) in the
// Amazon EC2 User Guide.
func (c *Client) StartInstances(ctx context.Context, params *StartInstancesInput, optFns ...func(*Options)) (*StartInstancesOutput, error) {
	if params == nil {
		params = &StartInstancesInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "StartInstances", params, optFns, c.addOperationStartInstancesMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*StartInstancesOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type StartInstancesInput struct {

	// The IDs of the instances.
	//
	// This member is required.
	InstanceIds []string

	// Reserved.
	AdditionalInfo *string

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation. Otherwise, it is
	// UnauthorizedOperation.
	DryRun *bool

	noSmithyDocumentSerde
}

type StartInstancesOutput struct {

	// Information about the started instances.
	StartingInstances []types.InstanceStateChange

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationStartInstancesMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpStartInstances{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpStartInstances{}, middleware.After)
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
	if err = addOpStartInstancesValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opStartInstances(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opStartInstances(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "StartInstances",
	}
}
