// Code generated by smithy-go-codegen DO NOT EDIT.

package sts

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/protocol/query"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	presignedurlcust "github.com/aws/aws-sdk-go-v2/service/internal/presigned-url"
	smithy "github.com/aws/smithy-go"
	smithydocument "github.com/aws/smithy-go/document"
	"github.com/aws/smithy-go/logging"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"net/http"
	"time"
)

const ServiceID = "STS"
const ServiceAPIVersion = "2011-06-15"

// Client provides the API client to make operations call for AWS Security Token
// Service.
type Client struct {
	options Options
}

// New returns an initialized Client based on the functional options. Provide
// additional functional options to further configure the behavior of the client,
// such as changing the client's endpoint or adding custom middleware behavior.
func New(options Options, optFns ...func(*Options)) *Client {
	options = options.Copy()

	resolveDefaultLogger(&options)

	resolveRetryer(&options)

	resolveHTTPClient(&options)

	resolveHTTPSignerV4(&options)

	resolveDefaultEndpointConfiguration(&options)

	for _, fn := range optFns {
		fn(&options)
	}

	client := &Client{
		options: options,
	}

	return client
}

type Options struct {
	// Set of options to modify how an operation is invoked. These apply to all
	// operations invoked for this client. Use functional options on operation call to
	// modify this list for per operation behavior.
	APIOptions []func(*middleware.Stack) error

	// Configures the events that will be sent to the configured logger.
	ClientLogMode aws.ClientLogMode

	// The credentials object to use when signing requests.
	Credentials aws.CredentialsProvider

	// The endpoint options to be used when attempting to resolve an endpoint.
	EndpointOptions EndpointResolverOptions

	// The service endpoint resolver.
	EndpointResolver EndpointResolver

	// Signature Version 4 (SigV4) Signer
	HTTPSignerV4 HTTPSignerV4

	// The logger writer interface to write logging messages to.
	Logger logging.Logger

	// The region to send requests to. (Required)
	Region string

	// Retryer guides how HTTP requests should be retried in case of recoverable
	// failures. When nil the API client will use a default retryer.
	Retryer aws.Retryer

	// The HTTP client to invoke API calls with. Defaults to client's default HTTP
	// implementation if nil.
	HTTPClient HTTPClient
}

// WithAPIOptions returns a functional option for setting the Client's APIOptions
// option.
func WithAPIOptions(optFns ...func(*middleware.Stack) error) func(*Options) {
	return func(o *Options) {
		o.APIOptions = append(o.APIOptions, optFns...)
	}
}

// WithEndpointResolver returns a functional option for setting the Client's
// EndpointResolver option.
func WithEndpointResolver(v EndpointResolver) func(*Options) {
	return func(o *Options) {
		o.EndpointResolver = v
	}
}

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Copy creates a clone where the APIOptions list is deep copied.
func (o Options) Copy() Options {
	to := o
	to.APIOptions = make([]func(*middleware.Stack) error, len(o.APIOptions))
	copy(to.APIOptions, o.APIOptions)
	return to
}
func (c *Client) invokeOperation(ctx context.Context, opID string, params interface{}, optFns []func(*Options), stackFns ...func(*middleware.Stack, Options) error) (result interface{}, metadata middleware.Metadata, err error) {
	ctx = middleware.ClearStackValues(ctx)
	stack := middleware.NewStack(opID, smithyhttp.NewStackRequest)
	options := c.options.Copy()
	for _, fn := range optFns {
		fn(&options)
	}

	for _, fn := range stackFns {
		if err := fn(stack, options); err != nil {
			return nil, metadata, err
		}
	}

	for _, fn := range options.APIOptions {
		if err := fn(stack); err != nil {
			return nil, metadata, err
		}
	}

	handler := middleware.DecorateHandler(smithyhttp.NewClientHandler(options.HTTPClient), stack)
	result, metadata, err = handler.Handle(ctx, params)
	if err != nil {
		err = &smithy.OperationError{
			ServiceID:     ServiceID,
			OperationName: opID,
			Err:           err,
		}
	}
	return result, metadata, err
}

type noSmithyDocumentSerde = smithydocument.NoSerde

func resolveDefaultLogger(o *Options) {
	if o.Logger != nil {
		return
	}
	o.Logger = logging.Nop{}
}

func addSetLoggerMiddleware(stack *middleware.Stack, o Options) error {
	return middleware.AddSetLoggerMiddleware(stack, o.Logger)
}

// NewFromConfig returns a new client from the provided config.
func NewFromConfig(cfg aws.Config, optFns ...func(*Options)) *Client {
	opts := Options{
		Region:        cfg.Region,
		HTTPClient:    cfg.HTTPClient,
		Credentials:   cfg.Credentials,
		APIOptions:    cfg.APIOptions,
		Logger:        cfg.Logger,
		ClientLogMode: cfg.ClientLogMode,
	}
	resolveAWSRetryerProvider(cfg, &opts)
	resolveAWSEndpointResolver(cfg, &opts)
	return New(opts, optFns...)
}

func resolveHTTPClient(o *Options) {
	if o.HTTPClient != nil {
		return
	}
	o.HTTPClient = awshttp.NewBuildableClient()
}

func resolveRetryer(o *Options) {
	if o.Retryer != nil {
		return
	}
	o.Retryer = retry.NewStandard()
}

func resolveAWSRetryerProvider(cfg aws.Config, o *Options) {
	if cfg.Retryer == nil {
		return
	}
	o.Retryer = cfg.Retryer()
}

func resolveAWSEndpointResolver(cfg aws.Config, o *Options) {
	if cfg.EndpointResolver == nil {
		return
	}
	o.EndpointResolver = withEndpointResolver(cfg.EndpointResolver, NewDefaultEndpointResolver())
}

func addClientUserAgent(stack *middleware.Stack) error {
	return awsmiddleware.AddSDKAgentKeyValue(awsmiddleware.APIMetadata, "sts", goModuleVersion)(stack)
}

func addHTTPSignerV4Middleware(stack *middleware.Stack, o Options) error {
	mw := v4.NewSignHTTPRequestMiddleware(v4.SignHTTPRequestMiddlewareOptions{
		CredentialsProvider: o.Credentials,
		Signer:              o.HTTPSignerV4,
		LogSigning:          o.ClientLogMode.IsSigning(),
	})
	return stack.Finalize.Add(mw, middleware.After)
}

type HTTPSignerV4 interface {
	SignHTTP(ctx context.Context, credentials aws.Credentials, r *http.Request, payloadHash string, service string, region string, signingTime time.Time, optFns ...func(*v4.SignerOptions)) error
}

func resolveHTTPSignerV4(o *Options) {
	if o.HTTPSignerV4 != nil {
		return
	}
	o.HTTPSignerV4 = newDefaultV4Signer(*o)
}

func newDefaultV4Signer(o Options) *v4.Signer {
	return v4.NewSigner(func(so *v4.SignerOptions) {
		so.Logger = o.Logger
		so.LogSigning = o.ClientLogMode.IsSigning()
	})
}

func addRetryMiddlewares(stack *middleware.Stack, o Options) error {
	mo := retry.AddRetryMiddlewaresOptions{
		Retryer:          o.Retryer,
		LogRetryAttempts: o.ClientLogMode.IsRetries(),
	}
	return retry.AddRetryMiddlewares(stack, mo)
}

func addRequestIDRetrieverMiddleware(stack *middleware.Stack) error {
	return awsmiddleware.AddRequestIDRetrieverMiddleware(stack)
}

func addResponseErrorMiddleware(stack *middleware.Stack) error {
	return awshttp.AddResponseErrorMiddleware(stack)
}

// HTTPPresignerV4 represents presigner interface used by presign url client
type HTTPPresignerV4 interface {
	PresignHTTP(
		ctx context.Context, credentials aws.Credentials, r *http.Request,
		payloadHash string, service string, region string, signingTime time.Time,
		optFns ...func(*v4.SignerOptions),
	) (url string, signedHeader http.Header, err error)
}

// PresignOptions represents the presign client options
type PresignOptions struct {

	// ClientOptions are list of functional options to mutate client options used by
	// the presign client.
	ClientOptions []func(*Options)

	// Presigner is the presigner used by the presign url client
	Presigner HTTPPresignerV4
}

func (o PresignOptions) copy() PresignOptions {
	clientOptions := make([]func(*Options), len(o.ClientOptions))
	copy(clientOptions, o.ClientOptions)
	o.ClientOptions = clientOptions
	return o
}

// WithPresignClientFromClientOptions is a helper utility to retrieve a function
// that takes PresignOption as input
func WithPresignClientFromClientOptions(optFns ...func(*Options)) func(*PresignOptions) {
	return withPresignClientFromClientOptions(optFns).options
}

type withPresignClientFromClientOptions []func(*Options)

func (w withPresignClientFromClientOptions) options(o *PresignOptions) {
	o.ClientOptions = append(o.ClientOptions, w...)
}

// PresignClient represents the presign url client
type PresignClient struct {
	client  *Client
	options PresignOptions
}

// NewPresignClient generates a presign client using provided API Client and
// presign options
func NewPresignClient(c *Client, optFns ...func(*PresignOptions)) *PresignClient {
	var options PresignOptions
	for _, fn := range optFns {
		fn(&options)
	}
	if len(options.ClientOptions) != 0 {
		c = New(c.options, options.ClientOptions...)
	}

	if options.Presigner == nil {
		options.Presigner = newDefaultV4Signer(c.options)
	}

	return &PresignClient{
		client:  c,
		options: options,
	}
}

func withNopHTTPClientAPIOption(o *Options) {
	o.HTTPClient = smithyhttp.NopClient{}
}

type presignConverter PresignOptions

func (c presignConverter) convertToPresignMiddleware(stack *middleware.Stack, options Options) (err error) {
	stack.Finalize.Clear()
	stack.Deserialize.Clear()
	stack.Build.Remove((*awsmiddleware.ClientRequestID)(nil).ID())
	stack.Build.Remove("UserAgent")
	pmw := v4.NewPresignHTTPRequestMiddleware(v4.PresignHTTPRequestMiddlewareOptions{
		CredentialsProvider: options.Credentials,
		Presigner:           c.Presigner,
		LogSigning:          options.ClientLogMode.IsSigning(),
	})
	err = stack.Finalize.Add(pmw, middleware.After)
	if err != nil {
		return err
	}
	// convert request to a GET request
	err = query.AddAsGetRequestMiddleware(stack)
	if err != nil {
		return err
	}
	err = presignedurlcust.AddAsIsPresigingMiddleware(stack)
	if err != nil {
		return err
	}
	return nil
}

func addRequestResponseLogging(stack *middleware.Stack, o Options) error {
	return stack.Deserialize.Add(&smithyhttp.RequestResponseLogger{
		LogRequest:          o.ClientLogMode.IsRequest(),
		LogRequestWithBody:  o.ClientLogMode.IsRequestWithBody(),
		LogResponse:         o.ClientLogMode.IsResponse(),
		LogResponseWithBody: o.ClientLogMode.IsResponseWithBody(),
	}, middleware.After)
}
