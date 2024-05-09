// Code generated by smithy-go-codegen DO NOT EDIT.

package ec2

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"time"
)

// Detaches an EBS volume from an instance. Make sure to unmount any file systems
// on the device within your operating system before detaching the volume. Failure
// to do so can result in the volume becoming stuck in the busy state while
// detaching. If this happens, detachment can be delayed indefinitely until you
// unmount the volume, force detachment, reboot the instance, or all three. If an
// EBS volume is the root device of an instance, it can't be detached while the
// instance is running. To detach the root volume, stop the instance first. When a
// volume with an Amazon Web Services Marketplace product code is detached from an
// instance, the product code is no longer associated with the instance. You can't
// detach or force detach volumes that are attached to Amazon ECS or Fargate tasks.
// Attempting to do this results in the UnsupportedOperationException exception
// with the Unable to detach volume attached to ECS tasks error message. For more
// information, see Detach an Amazon EBS volume (https://docs.aws.amazon.com/ebs/latest/userguide/ebs-detaching-volume.html)
// in the Amazon EBS User Guide.
func (c *Client) DetachVolume(ctx context.Context, params *DetachVolumeInput, optFns ...func(*Options)) (*DetachVolumeOutput, error) {
	if params == nil {
		params = &DetachVolumeInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DetachVolume", params, optFns, c.addOperationDetachVolumeMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DetachVolumeOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type DetachVolumeInput struct {

	// The ID of the volume.
	//
	// This member is required.
	VolumeId *string

	// The device name.
	Device *string

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation . Otherwise, it is
	// UnauthorizedOperation .
	DryRun *bool

	// Forces detachment if the previous detachment attempt did not occur cleanly (for
	// example, logging into an instance, unmounting the volume, and detaching
	// normally). This option can lead to data loss or a corrupted file system. Use
	// this option only as a last resort to detach a volume from a failed instance. The
	// instance won't have an opportunity to flush file system caches or file system
	// metadata. If you use this option, you must perform file system check and repair
	// procedures.
	Force *bool

	// The ID of the instance. If you are detaching a Multi-Attach enabled volume, you
	// must specify an instance ID.
	InstanceId *string

	noSmithyDocumentSerde
}

// Describes volume attachment details.
type DetachVolumeOutput struct {

	// The ARN of the Amazon ECS or Fargate task to which the volume is attached.
	AssociatedResource *string

	// The time stamp when the attachment initiated.
	AttachTime *time.Time

	// Indicates whether the EBS volume is deleted on instance termination.
	DeleteOnTermination *bool

	// The device name. If the volume is attached to a Fargate task, this parameter
	// returns null .
	Device *string

	// The ID of the instance. If the volume is attached to a Fargate task, this
	// parameter returns null .
	InstanceId *string

	// The service principal of Amazon Web Services service that owns the underlying
	// instance to which the volume is attached. This parameter is returned only for
	// volumes that are attached to Fargate tasks.
	InstanceOwningService *string

	// The attachment state of the volume.
	State types.VolumeAttachmentState

	// The ID of the volume.
	VolumeId *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationDetachVolumeMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsEc2query_serializeOpDetachVolume{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpDetachVolume{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "DetachVolume"); err != nil {
		return fmt.Errorf("add protocol finalizers: %v", err)
	}

	if err = addlegacyEndpointContextSetter(stack, options); err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = addClientRequestID(stack); err != nil {
		return err
	}
	if err = addComputeContentLength(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = addComputePayloadSHA256(stack); err != nil {
		return err
	}
	if err = addRetry(stack, options); err != nil {
		return err
	}
	if err = addRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = addRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addClientUserAgent(stack, options); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addSetLegacyContextSigningOptionsMiddleware(stack); err != nil {
		return err
	}
	if err = addOpDetachVolumeValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDetachVolume(options.Region), middleware.Before); err != nil {
		return err
	}
	if err = addRecursionDetection(stack); err != nil {
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
	if err = addDisableHTTPSMiddleware(stack, options); err != nil {
		return err
	}
	return nil
}

func newServiceMetadataMiddleware_opDetachVolume(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "DetachVolume",
	}
}