/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package common

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/rds/rdsutils"
	"github.com/aws/aws-sdk-go/service/redshift"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
	gcpcredentialspb "google.golang.org/genproto/googleapis/iam/credentials/v1"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	azureutils "github.com/gravitational/teleport/api/utils/azure"
	"github.com/gravitational/teleport/api/utils/retryutils"
	libauth "github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/native"
	"github.com/gravitational/teleport/lib/cloud"
	libazure "github.com/gravitational/teleport/lib/cloud/azure"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"
)

// azureVirtualMachineCacheTTL is the default TTL for Azure virtual machine
// cache entries.
const azureVirtualMachineCacheTTL = 5 * time.Minute

// Auth defines interface for creating auth tokens and TLS configurations.
type Auth interface {
	// GetRDSAuthToken generates RDS/Aurora auth token.
	GetRDSAuthToken(sessionCtx *Session) (string, error)
	// GetRedshiftAuthToken generates Redshift auth token.
	GetRedshiftAuthToken(sessionCtx *Session) (string, string, error)
	// GetCloudSQLAuthToken generates Cloud SQL auth token.
	GetCloudSQLAuthToken(ctx context.Context, sessionCtx *Session) (string, error)
	// GetCloudSQLPassword generates password for a Cloud SQL database user.
	GetCloudSQLPassword(ctx context.Context, sessionCtx *Session) (string, error)
	// GetAzureAccessToken generates Azure database access token.
	GetAzureAccessToken(ctx context.Context, sessionCtx *Session) (string, error)
	// GetAzureCacheForRedisToken retrieves auth token for Azure Cache for Redis.
	GetAzureCacheForRedisToken(ctx context.Context, sessionCtx *Session) (string, error)
	// GetTLSConfig builds the client TLS configuration for the session.
	GetTLSConfig(ctx context.Context, sessionCtx *Session) (*tls.Config, error)
	// GetAuthPreference returns the cluster authentication config.
	GetAuthPreference(ctx context.Context) (types.AuthPreference, error)
	// GetAzureIdentityResourceID returns the Azure identity resource ID
	// attached to the current compute instance. If Teleport is not running on
	// Azure VM returns an error.
	GetAzureIdentityResourceID(ctx context.Context, identityName string) (string, error)
	// Closer releases all resources used by authenticator.
	io.Closer
}

// AuthClient is an interface that defines a subset of libauth.Client's
// functions that are required for database auth.
type AuthClient interface {
	// GenerateDatabaseCert generates client certificate used by a database
	// service to authenticate with the database instance.
	GenerateDatabaseCert(ctx context.Context, req *proto.DatabaseCertRequest) (*proto.DatabaseCertResponse, error)
	// GetAuthPreference returns the cluster authentication config.
	GetAuthPreference(ctx context.Context) (types.AuthPreference, error)
}

// AuthConfig is the database access authenticator configuration.
type AuthConfig struct {
	// AuthClient is the cluster auth client.
	AuthClient AuthClient
	// Clients provides interface for obtaining cloud provider clients.
	Clients cloud.Clients
	// Clock is the clock implementation.
	Clock clockwork.Clock
	// Log is used for logging.
	Log logrus.FieldLogger
}

// CheckAndSetDefaults validates the config and sets defaults.
func (c *AuthConfig) CheckAndSetDefaults() error {
	if c.AuthClient == nil {
		return trace.BadParameter("missing AuthClient")
	}
	if c.Clients == nil {
		c.Clients = cloud.NewClients()
	}
	if c.Clock == nil {
		c.Clock = clockwork.NewRealClock()
	}
	if c.Log == nil {
		c.Log = logrus.WithField(trace.Component, "db:auth")
	}
	return nil
}

// dbAuth provides utilities for creating TLS configurations and
// generating auth tokens when connecting to databases.
type dbAuth struct {
	cfg AuthConfig
	// azureVirtualMachineCache caches the current Azure virtual machine.
	// Avoiding the need to query the metadata server on every database
	// connection.
	azureVirtualMachineCache *utils.FnCache
}

// NewAuth returns a new instance of database access authenticator.
func NewAuth(config AuthConfig) (Auth, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	azureVirtualMachineCache, err := utils.NewFnCache(utils.FnCacheConfig{
		TTL:   azureVirtualMachineCacheTTL,
		Clock: config.Clock,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &dbAuth{
		cfg:                      config,
		azureVirtualMachineCache: azureVirtualMachineCache,
	}, nil
}

// GetRDSAuthToken returns authorization token that will be used as a password
// when connecting to RDS and Aurora databases.
func (a *dbAuth) GetRDSAuthToken(sessionCtx *Session) (string, error) {
	awsSession, err := a.cfg.Clients.GetAWSSession(sessionCtx.Database.GetAWS().Region)
	if err != nil {
		return "", trace.Wrap(err)
	}
	a.cfg.Log.Debugf("Generating RDS auth token for %s.", sessionCtx)
	token, err := rdsutils.BuildAuthToken(
		sessionCtx.Database.GetURI(),
		sessionCtx.Database.GetAWS().Region,
		sessionCtx.DatabaseUser,
		awsSession.Config.Credentials)
	if err != nil {
		policy, getPolicyErr := sessionCtx.Database.GetIAMPolicy()
		if getPolicyErr != nil {
			policy = fmt.Sprintf("failed to generate IAM policy: %v", getPolicyErr)
		}
		return "", trace.AccessDenied(`Could not generate RDS IAM auth token:

  %v

Make sure that Teleport database agent's IAM policy is attached and has "rds-connect"
permissions (note that IAM changes may take a few minutes to propagate):

%v
`, err, policy)
	}
	return token, nil
}

// GetRedshiftAuthToken returns authorization token that will be used as a
// password when connecting to Redshift databases.
func (a *dbAuth) GetRedshiftAuthToken(sessionCtx *Session) (string, string, error) {
	awsSession, err := a.cfg.Clients.GetAWSSession(sessionCtx.Database.GetAWS().Region)
	if err != nil {
		return "", "", trace.Wrap(err)
	}
	a.cfg.Log.Debugf("Generating Redshift auth token for %s.", sessionCtx)
	resp, err := redshift.New(awsSession).GetClusterCredentials(&redshift.GetClusterCredentialsInput{
		ClusterIdentifier: aws.String(sessionCtx.Database.GetAWS().Redshift.ClusterID),
		DbUser:            aws.String(sessionCtx.DatabaseUser),
		DbName:            aws.String(sessionCtx.DatabaseName),
		// TODO(r0mant): Do not auto-create database account if DbUser doesn't
		// exist for now, but it may be potentially useful in future.
		AutoCreate: aws.Bool(false),
		// TODO(r0mant): List of additional groups DbUser will join for the
		// session. Do we need to let people control this?
		DbGroups: []*string{},
	})
	if err != nil {
		policy, getPolicyErr := sessionCtx.Database.GetIAMPolicy()
		if getPolicyErr != nil {
			policy = fmt.Sprintf("failed to generate IAM policy: %v", getPolicyErr)
		}
		return "", "", trace.AccessDenied(`Could not generate Redshift IAM auth token:

  %v

Make sure that Teleport database agent's IAM policy is attached and has permissions
to generate Redshift credentials (note that IAM changes may take a few minutes to
propagate):

%v
`, err, policy)
	}
	return *resp.DbUser, *resp.DbPassword, nil
}

// GetCloudSQLAuthToken returns authorization token that will be used as a
// password when connecting to Cloud SQL databases.
func (a *dbAuth) GetCloudSQLAuthToken(ctx context.Context, sessionCtx *Session) (string, error) {
	gcpIAM, err := a.cfg.Clients.GetGCPIAMClient(ctx)
	if err != nil {
		return "", trace.Wrap(err)
	}
	a.cfg.Log.Debugf("Generating GCP auth token for %s.", sessionCtx)
	resp, err := gcpIAM.GenerateAccessToken(ctx,
		&gcpcredentialspb.GenerateAccessTokenRequest{
			// From GenerateAccessToken docs:
			//
			// The resource name of the service account for which the credentials
			// are requested, in the following format:
			//   projects/-/serviceAccounts/{ACCOUNT_EMAIL_OR_UNIQUEID}
			Name: fmt.Sprintf("projects/-/serviceAccounts/%v.gserviceaccount.com", sessionCtx.DatabaseUser),
			// From GenerateAccessToken docs:
			//
			// Code to identify the scopes to be included in the OAuth 2.0 access
			// token:
			//   https://developers.google.com/identity/protocols/oauth2/scopes
			//   https://developers.google.com/identity/protocols/oauth2/scopes#sqladmin
			Scope: []string{
				"https://www.googleapis.com/auth/sqlservice.admin",
			},
		})
	if err != nil {
		return "", trace.AccessDenied(`Could not generate GCP IAM auth token:

  %v

Make sure Teleport db service has "Service Account Token Creator" GCP IAM role,
or "iam.serviceAccounts.getAccessToken" IAM permission.
`, err)
	}
	return resp.AccessToken, nil
}

// GetCloudSQLPassword updates the specified database user's password to a
// random value using GCP Cloud SQL Admin API.
//
// It is used to generate a one-time password when connecting to GCP MySQL
// databases which don't support IAM authentication.
func (a *dbAuth) GetCloudSQLPassword(ctx context.Context, sessionCtx *Session) (string, error) {
	gcpCloudSQL, err := a.cfg.Clients.GetGCPSQLAdminClient(ctx)
	if err != nil {
		return "", trace.Wrap(err)
	}
	a.cfg.Log.Debugf("Generating GCP user password for %s.", sessionCtx)
	token, err := utils.CryptoRandomHex(libauth.TokenLenBytes)
	if err != nil {
		return "", trace.Wrap(err)
	}
	// Cloud SQL will return 409 to a user update operation if there is another
	// one in progress, so retry upon encountering it. Also, be nice to the API
	// and retry with a backoff.
	retry, err := retryutils.NewConstant(time.Second)
	if err != nil {
		return "", trace.Wrap(err)
	}
	retryCtx, cancel := context.WithTimeout(ctx, defaults.DatabaseConnectTimeout)
	defer cancel()
	err = retry.For(retryCtx, func() error {
		err := a.updateCloudSQLUser(ctx, sessionCtx, gcpCloudSQL, &sqladmin.User{
			Password: token,
		})
		if err != nil && !trace.IsCompareFailed(ConvertError(err)) { // We only want to retry on 409.
			return retryutils.PermanentRetryError(err)
		}
		return trace.Wrap(err)
	})
	if err != nil {
		return "", trace.Wrap(err)
	}
	return token, nil
}

// updateCloudSQLUser makes a request to Cloud SQL API to update the provided user.
func (a *dbAuth) updateCloudSQLUser(ctx context.Context, sessionCtx *Session, gcpCloudSQL cloud.GCPSQLAdminClient, user *sqladmin.User) error {
	err := gcpCloudSQL.UpdateUser(ctx, sessionCtx.Database, sessionCtx.DatabaseUser, user)
	if err != nil {
		return trace.AccessDenied(`Could not update Cloud SQL user %q password:

  %v

Make sure Teleport db service has "Cloud SQL Admin" GCP IAM role, or
"cloudsql.users.update" IAM permission.
`, sessionCtx.DatabaseUser, err)
	}
	return nil
}

// GetAzureAccessToken generates Azure database access token.
func (a *dbAuth) GetAzureAccessToken(ctx context.Context, sessionCtx *Session) (string, error) {
	a.cfg.Log.Debugf("Generating Azure access token for %s.", sessionCtx)
	cred, err := a.cfg.Clients.GetAzureCredential()
	if err != nil {
		return "", trace.Wrap(err)
	}
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{
			// Access token scope for connecting to Postgres/MySQL database.
			"https://ossrdbms-aad.database.windows.net/.default",
		},
	})
	if err != nil {
		return "", trace.Wrap(err)
	}
	return token.Token, nil
}

// GetAzureCacheForRedisToken retrieves auth token for Azure Cache for Redis.
func (a *dbAuth) GetAzureCacheForRedisToken(ctx context.Context, sessionCtx *Session) (string, error) {
	resourceID, err := arm.ParseResourceID(sessionCtx.Database.GetAzure().ResourceID)
	if err != nil {
		return "", trace.Wrap(err)
	}

	var client libazure.CacheForRedisClient
	switch resourceID.ResourceType.String() {
	case "Microsoft.Cache/Redis":
		client, err = a.cfg.Clients.GetAzureRedisClient(resourceID.SubscriptionID)
		if err != nil {
			return "", trace.Wrap(err)
		}
	case "Microsoft.Cache/redisEnterprise", "Microsoft.Cache/redisEnterprise/databases":
		client, err = a.cfg.Clients.GetAzureRedisEnterpriseClient(resourceID.SubscriptionID)
		if err != nil {
			return "", trace.Wrap(err)
		}
	default:
		return "", trace.BadParameter("unknown Azure Cache for Redis resource type: %v", resourceID.ResourceType)
	}
	token, err := client.GetToken(ctx, sessionCtx.Database.GetAzure().ResourceID)
	if err != nil {
		// Some Azure error messages are long, multi-lined, and may even
		// contain divider lines like "------". It's unreadable in redis-cli as
		// the message has to be merged to a single line string. Thus logging
		// the original error as debug and returning a more user friendly
		// message.
		a.cfg.Log.WithError(err).Debugf("Failed to get token for Azure Redis %q.", sessionCtx.Database.GetName())
		switch {
		case trace.IsAccessDenied(err):
			return "", trace.AccessDenied("Failed to get token for Azure Redis %q. Please make sure the database agent has the \"listKeys\" permission to the database.", sessionCtx.Database.GetName())
		case trace.IsNotFound(err):
			// Note that Azure Cache for Redis should always have both keys
			// generated at all time. Here just checking in case something
			// wrong with the API.
			return "", trace.AccessDenied("Failed to get token for Azure Redis %q. Please make sure either the primary key or the secondary key is generated.", sessionCtx.Database.GetName())
		default:
			return "", trace.Errorf("Failed to get token for Azure Redis %q.", sessionCtx.Database.GetName())
		}
	}
	return token, nil
}

// GetTLSConfig builds the client TLS configuration for the session.
//
// For RDS/Aurora, the config must contain RDS root certificate as a trusted
// authority. For on-prem we generate a client certificate signed by the host
// CA used to authenticate.
func (a *dbAuth) GetTLSConfig(ctx context.Context, sessionCtx *Session) (*tls.Config, error) {
	dbTLSConfig := sessionCtx.Database.GetTLS()

	// Mode won't be set for older clients. We will default to VerifyFull then - the same as before.
	switch dbTLSConfig.Mode {
	case types.DatabaseTLSMode_INSECURE:
		return a.getTLSConfigInsecure(ctx, sessionCtx)
	case types.DatabaseTLSMode_VERIFY_CA:
		return a.getTLSConfigVerifyCA(ctx, sessionCtx)
	default:
		return a.getTLSConfigVerifyFull(ctx, sessionCtx)
	}
}

// getTLSConfigVerifyFull returns tls.Config with full verification enabled ('verify-full' mode).
// Config also includes database specific adjustment.
func (a *dbAuth) getTLSConfigVerifyFull(ctx context.Context, sessionCtx *Session) (*tls.Config, error) {
	tlsConfig := &tls.Config{}

	// Add CA certificate to the trusted pool if it's present, e.g. when
	// connecting to RDS/Aurora which require AWS CA or when was provided in config file.
	//
	// Some databases may also require the system cert pool, e.g Azure Redis.
	if err := setupTLSConfigRootCAs(tlsConfig, sessionCtx); err != nil {
		return nil, trace.Wrap(err)
	}

	// You connect to Cloud SQL instances by IP and the certificate presented
	// by the instance does not contain IP SANs so the default "full" certificate
	// verification will always fail.
	//
	// In the docs they recommend disabling hostname verification when connecting
	// e.g. with psql (verify-ca mode) reasoning that it's not required since
	// CA is instance-specific:
	//   https://cloud.google.com/sql/docs/postgres/connect-admin-ip
	//
	// They do encode <project-id>:<instance-id> in the CN field, which also
	// wouldn't validate by default since CN has been deprecated and server
	// name verification ignores it starting from Go 1.15.
	//
	// For this reason we're setting ServerName to <project-id>:<instance-id>,
	// disabling default certificate verification and validating it ourselves.
	//
	// See the following Go issue for more context:
	//   https://github.com/golang/go/issues/40748
	if sessionCtx.Database.IsCloudSQL() {
		// Cloud SQL server presented certificates encode instance names as
		// "<project-id>:<instance-id>" in CommonName. This is verified against
		// the ServerName in a custom connection verification step (see below).
		tlsConfig.ServerName = sessionCtx.Database.GetGCP().GetServerName()
		// This just disables default verification.
		tlsConfig.InsecureSkipVerify = true
		// This will verify CN and cert chain on each connection.
		tlsConfig.VerifyConnection = getVerifyCloudSQLCertificate(tlsConfig.RootCAs)
	}

	// Setup server name for verification.
	if err := setupTLSConfigServerName(tlsConfig, sessionCtx); err != nil {
		return nil, trace.Wrap(err)
	}

	// RDS/Aurora/Redshift/ElastiCache and Cloud SQL auth is done with an auth
	// token so don't generate a client certificate and exit here.
	if sessionCtx.Database.IsCloudHosted() {
		return tlsConfig, nil
	}

	// Otherwise, when connecting to an onprem database, generate a client
	// certificate. The database instance should be configured with
	// Teleport's CA obtained with 'tctl auth sign --type=db'.
	return a.appendClientCert(ctx, sessionCtx, tlsConfig)
}

// getTLSConfigInsecure generates tls.Config when TLS mode is equal to 'insecure'.
// Generated configuration will accept any certificate provided by database.
func (a *dbAuth) getTLSConfigInsecure(ctx context.Context, sessionCtx *Session) (*tls.Config, error) {
	tlsConfig, err := a.getTLSConfigVerifyFull(ctx, sessionCtx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Accept any certificate provided by database.
	tlsConfig.InsecureSkipVerify = true
	// Remove certificate validation if set.
	tlsConfig.VerifyConnection = nil

	return tlsConfig, nil
}

// getTLSConfigVerifyCA generates tls.Config when TLS mode is equal to 'verify-ca'.
// Generated configuration is the same as 'verify-full' except the server name
// verification is disabled.
func (a *dbAuth) getTLSConfigVerifyCA(ctx context.Context, sessionCtx *Session) (*tls.Config, error) {
	tlsConfig, err := a.getTLSConfigVerifyFull(ctx, sessionCtx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Base on https://github.com/golang/go/blob/master/src/crypto/tls/example_test.go#L193-L208
	// Set InsecureSkipVerify to skip the default validation we are
	// replacing. This will not disable VerifyConnection.
	tlsConfig.InsecureSkipVerify = true
	tlsConfig.VerifyConnection = verifyConnectionFunc(tlsConfig.RootCAs)
	// ServerName is irrelevant in this case. Set it to default value to make it explicit.
	tlsConfig.ServerName = ""

	return tlsConfig, nil
}

// appendClientCert generates a client certificate and appends it to the provided tlsConfig.
func (a *dbAuth) appendClientCert(ctx context.Context, sessionCtx *Session, tlsConfig *tls.Config) (*tls.Config, error) {
	cert, cas, err := a.getClientCert(ctx, sessionCtx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tlsConfig.Certificates = []tls.Certificate{*cert}
	for _, ca := range cas {
		if !tlsConfig.RootCAs.AppendCertsFromPEM(ca) {
			return nil, trace.BadParameter("failed to append CA certificate to the pool")
		}
	}

	return tlsConfig, nil
}

// setupTLSConfigRootCAs initializes the root CA cert pool for the provided
// tlsConfig based on session context.
func setupTLSConfigRootCAs(tlsConfig *tls.Config, sessionCtx *Session) error {
	// Start with an empty pool.
	tlsConfig.RootCAs = x509.NewCertPool()

	// If CA is provided by the database object, always use it.
	if len(sessionCtx.Database.GetCA()) != 0 {
		if !tlsConfig.RootCAs.AppendCertsFromPEM([]byte(sessionCtx.Database.GetCA())) {
			return trace.BadParameter("invalid server CA certificate")
		}
		return nil
	}

	// Overwrite with the system cert pool, if required.
	if shouldUseSystemCertPool(sessionCtx) {
		systemCertPool, err := x509.SystemCertPool()
		if err != nil {
			return trace.Wrap(err)
		}
		tlsConfig.RootCAs = systemCertPool
		return nil
	}

	// Use the empty pool. Client cert will be added later.
	return nil
}

// shouldUseSystemCertPool returns true for database servers presenting
// certificates signed by publicly trusted CAs so a system cert pool can be
// used.
func shouldUseSystemCertPool(sessionCtx *Session) bool {
	switch sessionCtx.Database.GetType() {
	// Azure databases either use Baltimore Root CA or DigiCert Global Root G2.
	//
	// https://docs.microsoft.com/en-us/azure/postgresql/concepts-ssl-connection-security
	// https://docs.microsoft.com/en-us/azure/mysql/howto-configure-ssl
	case types.DatabaseTypeAzure:
		return true

	case types.DatabaseTypeRDSProxy:
		// AWS RDS Proxy uses Amazon Root CAs.
		//
		// https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy.howitworks.html#rds-proxy-security.tls
		return true
	}
	return false
}

// setupTLSConfigServerName initializes the server name for the provided
// tlsConfig based on session context.
func setupTLSConfigServerName(tlsConfig *tls.Config, sessionCtx *Session) error {
	// Use user provided server name if set. Override the current value if needed.
	if dbTLSConfig := sessionCtx.Database.GetTLS(); dbTLSConfig.ServerName != "" {
		tlsConfig.ServerName = dbTLSConfig.ServerName
		return nil
	}

	// If server name is set prior to this function, use that.
	if tlsConfig.ServerName != "" {
		return nil
	}

	switch sessionCtx.Database.GetProtocol() {
	case defaults.ProtocolMongoDB:
		// Don't set the ServerName when connecting to a MongoDB cluster - in case
		// of replica set the driver may dial multiple servers and will set
		// ServerName itself.
		return nil

	case defaults.ProtocolRedis:
		// Azure Redis servers always serve the certificates with the proper
		// hostnames. However, OSS cluster mode may redirect to an IP address,
		// and without correct ServerName the handshake will fail as the IPs
		// are not in SANs.
		if sessionCtx.Database.IsAzure() {
			serverName, err := azureutils.GetHostFromRedisURI(sessionCtx.Database.GetURI())
			if err != nil {
				return trace.Wrap(err)
			}

			tlsConfig.ServerName = serverName
			return nil
		}

		// Redis is using custom URI schema.
		return nil

	default:
		// For other databases we're always connecting to the server specified
		// in URI so set ServerName ourselves.
		addr, err := utils.ParseAddr(sessionCtx.Database.GetURI())
		if err != nil {
			return trace.Wrap(err)
		}
		tlsConfig.ServerName = addr.Host()
		return nil
	}
}

// verifyConnectionFunc returns a certificate validation function. serverName if empty will skip the hostname validation.
func verifyConnectionFunc(rootCAs *x509.CertPool) func(cs tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return trace.AccessDenied("database didn't present any certificate during initial handshake")
		}

		opts := x509.VerifyOptions{
			Roots:         rootCAs,
			DNSName:       "", // Skip server name validation
			Intermediates: x509.NewCertPool(),
		}
		// From Go Docs:
		// The first element (zero index) is the leaf certificate that the connection is verified against.
		//
		// In order to verify the whole chain we need to add all certificates on pos [1:] as intermediates
		// and call Verify() on the [0] one. Root is provided as an input to this function.
		for _, cert := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}

		_, err := cs.PeerCertificates[0].Verify(opts)
		return trace.Wrap(err)
	}
}

// getClientCert signs an ephemeral client certificate used by this
// server to authenticate with the database instance.
func (a *dbAuth) getClientCert(ctx context.Context, sessionCtx *Session) (cert *tls.Certificate, cas [][]byte, err error) {
	privateKey, err := native.GeneratePrivateKey()
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	// Postgres requires the database username to be encoded as a common
	// name in the client certificate.
	subject := pkix.Name{CommonName: sessionCtx.DatabaseUser}
	csr, err := tlsca.GenerateCertificateRequestPEM(subject, privateKey)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	// TODO(r0mant): Cache database certificates to avoid expensive generate
	// operation on each connection.
	a.cfg.Log.Debugf("Generating client certificate for %s.", sessionCtx)
	resp, err := a.cfg.AuthClient.GenerateDatabaseCert(ctx, &proto.DatabaseCertRequest{
		CSR: csr,
		TTL: proto.Duration(sessionCtx.Identity.Expires.Sub(a.cfg.Clock.Now())),
	})
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	clientCert, err := privateKey.TLSCertificate(resp.Cert)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	return &clientCert, resp.CACerts, nil
}

// GetAuthPreference returns the cluster authentication config.
func (a *dbAuth) GetAuthPreference(ctx context.Context) (types.AuthPreference, error) {
	return a.cfg.AuthClient.GetAuthPreference(ctx)
}

// GetAzureIdentityResourceID returns the Azure identity resource ID attached to
// the current compute instance.
func (a *dbAuth) GetAzureIdentityResourceID(ctx context.Context, identityName string) (string, error) {
	if identityName == "" {
		return "", trace.BadParameter("empty identity name")
	}

	vm, err := utils.FnCacheGet(ctx, a.azureVirtualMachineCache, "", a.getCurrentAzureVM)
	if err != nil {
		return "", trace.Wrap(err)
	}

	for _, identity := range vm.Identities {
		if matchAzureResourceName(identity.ResourceID, identityName) {
			return identity.ResourceID, nil
		}
	}

	return "", trace.NotFound("could not find identity %q attached to the instance", identityName)
}

// getCurrentAzureVM fetches current Azure Virtual Machine struct. If Teleport
// is not running on Azure, returns an error.
func (a *dbAuth) getCurrentAzureVM(ctx context.Context) (*libazure.VirtualMachine, error) {
	metadataClient, err := a.cfg.Clients.GetInstanceMetadataClient(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if metadataClient.GetType() != types.InstanceMetadataTypeAzure {
		return nil, trace.BadParameter("fetching Azure identity resource ID is only supported on Azure")
	}

	instanceID, err := metadataClient.GetID(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	parsedInstanceID, err := arm.ParseResourceID(instanceID)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	vmClient, err := a.cfg.Clients.GetAzureVirtualMachinesClient(parsedInstanceID.SubscriptionID)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	vm, err := vmClient.Get(ctx, instanceID)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return vm, nil
}

// Close releases all resources used by authenticator.
func (a *dbAuth) Close() error {
	return a.cfg.Clients.Close()
}

// getVerifyCloudSQLCertificate returns a function that performs verification
// of server certificate presented by a Cloud SQL database instance.
func getVerifyCloudSQLCertificate(roots *x509.CertPool) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) < 1 {
			return trace.AccessDenied("Cloud SQL instance didn't present a certificate")
		}
		// CN has been deprecated for a while, but Cloud SQL instances still use
		// it to encode instance name in the form of <project-id>:<instance-id>.
		commonName := cs.PeerCertificates[0].Subject.CommonName
		if commonName != cs.ServerName {
			return trace.AccessDenied("Cloud SQL certificate CommonName validation failed: expected %q, got %q", cs.ServerName, commonName)
		}
		opts := x509.VerifyOptions{Roots: roots, Intermediates: x509.NewCertPool()}
		for _, cert := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}
		_, err := cs.PeerCertificates[0].Verify(opts)
		return err
	}
}

// matchAzureResourceName receives a resource ID and checks if the resource name
// matches.
func matchAzureResourceName(resourceID, name string) bool {
	parsedResource, err := arm.ParseResourceID(resourceID)
	if err != nil {
		return false
	}

	return parsedResource.Name == name
}
