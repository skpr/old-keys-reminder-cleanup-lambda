// Code generated by smithy-go-codegen DO NOT EDIT.

package ses

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/ses/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Creates an association between a configuration set and a custom domain for open
// and click event tracking.
//
// By default, images and links used for tracking open and click events are hosted
// on domains operated by Amazon SES. You can configure a subdomain of your own to
// handle these events. For information about using custom domains, see the [Amazon SES Developer Guide].
//
// [Amazon SES Developer Guide]: https://docs.aws.amazon.com/ses/latest/dg/configure-custom-open-click-domains.html
func (c *Client) CreateConfigurationSetTrackingOptions(ctx context.Context, params *CreateConfigurationSetTrackingOptionsInput, optFns ...func(*Options)) (*CreateConfigurationSetTrackingOptionsOutput, error) {
	if params == nil {
		params = &CreateConfigurationSetTrackingOptionsInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "CreateConfigurationSetTrackingOptions", params, optFns, c.addOperationCreateConfigurationSetTrackingOptionsMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*CreateConfigurationSetTrackingOptionsOutput)
	out.ResultMetadata = metadata
	return out, nil
}

// Represents a request to create an open and click tracking option object in a
// configuration set.
type CreateConfigurationSetTrackingOptionsInput struct {

	// The name of the configuration set that the tracking options should be
	// associated with.
	//
	// This member is required.
	ConfigurationSetName *string

	// A domain that is used to redirect email recipients to an Amazon SES-operated
	// domain. This domain captures open and click events generated by Amazon SES
	// emails.
	//
	// For more information, see [Configuring Custom Domains to Handle Open and Click Tracking] in the Amazon SES Developer Guide.
	//
	// [Configuring Custom Domains to Handle Open and Click Tracking]: https://docs.aws.amazon.com/ses/latest/dg/configure-custom-open-click-domains.html
	//
	// This member is required.
	TrackingOptions *types.TrackingOptions

	noSmithyDocumentSerde
}

// An empty element returned on a successful request.
type CreateConfigurationSetTrackingOptionsOutput struct {
	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationCreateConfigurationSetTrackingOptionsMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsAwsquery_serializeOpCreateConfigurationSetTrackingOptions{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsAwsquery_deserializeOpCreateConfigurationSetTrackingOptions{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "CreateConfigurationSetTrackingOptions"); err != nil {
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
	if err = addSpanRetryLoop(stack, options); err != nil {
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
	if err = addTimeOffsetBuild(stack, c); err != nil {
		return err
	}
	if err = addUserAgentRetryMode(stack, options); err != nil {
		return err
	}
	if err = addOpCreateConfigurationSetTrackingOptionsValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opCreateConfigurationSetTrackingOptions(options.Region), middleware.Before); err != nil {
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
	if err = addSpanInitializeStart(stack); err != nil {
		return err
	}
	if err = addSpanInitializeEnd(stack); err != nil {
		return err
	}
	if err = addSpanBuildRequestStart(stack); err != nil {
		return err
	}
	if err = addSpanBuildRequestEnd(stack); err != nil {
		return err
	}
	return nil
}

func newServiceMetadataMiddleware_opCreateConfigurationSetTrackingOptions(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "CreateConfigurationSetTrackingOptions",
	}
}