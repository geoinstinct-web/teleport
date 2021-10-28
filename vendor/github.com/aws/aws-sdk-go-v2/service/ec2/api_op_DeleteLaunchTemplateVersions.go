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

// Deletes one or more versions of a launch template. You cannot delete the default
// version of a launch template; you must first assign a different version as the
// default. If the default version is the only version for the launch template, you
// must delete the entire launch template using DeleteLaunchTemplate.
func (c *Client) DeleteLaunchTemplateVersions(ctx context.Context, params *DeleteLaunchTemplateVersionsInput, optFns ...func(*Options)) (*DeleteLaunchTemplateVersionsOutput, error) {
	if params == nil {
		params = &DeleteLaunchTemplateVersionsInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DeleteLaunchTemplateVersions", params, optFns, c.addOperationDeleteLaunchTemplateVersionsMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DeleteLaunchTemplateVersionsOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type DeleteLaunchTemplateVersionsInput struct {

	// The version numbers of one or more launch template versions to delete.
	//
	// This member is required.
	Versions []string

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation. Otherwise, it is
	// UnauthorizedOperation.
	DryRun *bool

	// The ID of the launch template. You must specify either the launch template ID or
	// launch template name in the request.
	LaunchTemplateId *string

	// The name of the launch template. You must specify either the launch template ID
	// or launch template name in the request.
	LaunchTemplateName *string

	noSmithyDocumentSerde
}

type DeleteLaunchTemplateVersionsOutput struct {

	// Information about the launch template versions that were successfully deleted.
	SuccessfullyDeletedLaunchTemplateVersions []types.DeleteLaunchTemplateVersionsResponseSuccessItem

	// Information about the launch template versions that could not be deleted.
	UnsuccessfullyDeletedLaunchTemplateVersions []types.DeleteLaunchTemplateVersionsResponseErrorItem

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationDeleteLaunchTemplateVersionsMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpDeleteLaunchTemplateVersions{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpDeleteLaunchTemplateVersions{}, middleware.After)
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
	if err = addOpDeleteLaunchTemplateVersionsValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDeleteLaunchTemplateVersions(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opDeleteLaunchTemplateVersions(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "DeleteLaunchTemplateVersions",
	}
}
