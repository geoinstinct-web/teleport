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

// Creates an import volume task using metadata from the specified disk image. This
// API action supports only single-volume VMs. To import multi-volume VMs, use
// ImportImage instead. To import a disk to a snapshot, use ImportSnapshot instead.
// This API action is not supported by the Command Line Interface (CLI). For
// information about using the Amazon EC2 CLI, which is deprecated, see Importing
// Disks to Amazon EBS
// (https://awsdocs.s3.amazonaws.com/EC2/ec2-clt.pdf#importing-your-volumes-into-amazon-ebs)
// in the Amazon EC2 CLI Reference PDF file. For information about the import
// manifest referenced by this API action, see VM Import Manifest
// (https://docs.aws.amazon.com/AWSEC2/latest/APIReference/manifest.html).
func (c *Client) ImportVolume(ctx context.Context, params *ImportVolumeInput, optFns ...func(*Options)) (*ImportVolumeOutput, error) {
	if params == nil {
		params = &ImportVolumeInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "ImportVolume", params, optFns, c.addOperationImportVolumeMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*ImportVolumeOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type ImportVolumeInput struct {

	// The Availability Zone for the resulting EBS volume.
	//
	// This member is required.
	AvailabilityZone *string

	// The disk image.
	//
	// This member is required.
	Image *types.DiskImageDetail

	// The volume size.
	//
	// This member is required.
	Volume *types.VolumeDetail

	// A description of the volume.
	Description *string

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation. Otherwise, it is
	// UnauthorizedOperation.
	DryRun *bool

	noSmithyDocumentSerde
}

type ImportVolumeOutput struct {

	// Information about the conversion task.
	ConversionTask *types.ConversionTask

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationImportVolumeMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpImportVolume{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpImportVolume{}, middleware.After)
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
	if err = addOpImportVolumeValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opImportVolume(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opImportVolume(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "ImportVolume",
	}
}
