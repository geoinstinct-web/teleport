/*
Copyright 2022 Gravitational, Inc.

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

package sqlserver

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"

	"github.com/gravitational/trace"
	"github.com/jcmturner/gokrb5/v8/client"
	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/azuread"
	"github.com/microsoft/go-mssqldb/msdsn"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/windows"
	"github.com/gravitational/teleport/lib/srv/db/common"
	"github.com/gravitational/teleport/lib/srv/db/sqlserver/kinit"
	"github.com/gravitational/teleport/lib/srv/db/sqlserver/protocol"
)

const (
	// ResourceIDDSNKey represents the resource ID DSN parameter key. This value
	// is defined by the go-mssqldb library.
	ResourceIDDSNKey = "resource id"
	// FederatedAuthDSNKey represents the federated auth DSN parameter key. This
	// value is defined by the go-mssqldb library.
	FederatedAuthDSNKey = "fedauth"
)

// Connector defines an interface for connecting to a SQL Server so it can be
// swapped out in tests.
type Connector interface {
	Connect(context.Context, *common.Session, *protocol.Login7Packet) (io.ReadWriteCloser, []mssql.Token, error)
}

type connector struct {
	// Auth is the database auth client
	DBAuth common.Auth
	// AuthClient is the teleport client
	AuthClient windows.AuthInterface
	// DataDir is the Teleport data directory
	DataDir string

	kinitCommandGenerator kinit.CommandGenerator
}

var errBadKerberosConfig = errors.New("configuration must have either keytab or kdc_host_name and ldap_cert")

func (c *connector) getKerberosClient(ctx context.Context, sessionCtx *common.Session) (*client.Client, error) {
	switch {
	case sessionCtx.Database.GetAD().KeytabFile != "":
		kt, err := c.keytabClient(sessionCtx)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return kt, nil
	case sessionCtx.Database.GetAD().KDCHostName != "" && sessionCtx.Database.GetAD().LDAPCert != "":
		kt, err := c.kinitClient(ctx, sessionCtx, c.AuthClient, c.DataDir)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return kt, nil

	}
	return nil, trace.Wrap(errBadKerberosConfig)
}

// Connect connects to the target SQL Server with Kerberos authentication.
func (c *connector) Connect(ctx context.Context, sessionCtx *common.Session, loginPacket *protocol.Login7Packet) (io.ReadWriteCloser, []mssql.Token, error) {
	host, port, err := net.SplitHostPort(sessionCtx.Database.GetURI())
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	portI, err := strconv.ParseUint(port, 10, 64)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	tlsConfig, err := c.DBAuth.GetTLSConfig(ctx, sessionCtx)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	// Pass all login options from the client to the server.
	options := msdsn.LoginOptions{
		OptionFlags1: loginPacket.OptionFlags1(),
		OptionFlags2: loginPacket.OptionFlags2(),
		TypeFlags:    loginPacket.TypeFlags(),
	}

	dsnConfig := msdsn.Config{
		Host:         host,
		Port:         portI,
		Database:     sessionCtx.DatabaseName,
		LoginOptions: options,
		Encryption:   msdsn.EncryptionRequired,
		TLSConfig:    tlsConfig,
		PacketSize:   loginPacket.PacketSize(),
		Protocols:    []string{"tcp"},
	}

	var connector *mssql.Connector
	switch {
	case sessionCtx.Database.IsAzure() && sessionCtx.Database.GetAD().Domain == "":
		// If the client is connecting to Azure SQL, and no AD configuration is
		// provided, authenticate using the Azure AD Integrated authentication
		// method.
		connector, err = c.getAzureConnector(ctx, sessionCtx, dsnConfig)
	case sessionCtx.Database.GetType() == types.DatabaseTypeRDSProxy:
		connector, err = c.getAccessTokenConnector(ctx, sessionCtx, dsnConfig)
	default:
		connector, err = c.getKerberosConnector(ctx, sessionCtx, dsnConfig)
	}
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	conn, err := connector.Connect(ctx)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	mssqlConn, ok := conn.(*mssql.Conn)
	if !ok {
		return nil, nil, trace.BadParameter("expected *mssql.Conn, got: %T", conn)
	}

	// Return all login flags returned by the server so that they can be passed
	// back to the client.
	return mssqlConn.GetUnderlyingConn(), mssqlConn.GetLoginFlags(), nil
}

// getKerberosConnector generates a Kerberos connector using proper Kerberos
// client.
func (c *connector) getKerberosConnector(ctx context.Context, sessionCtx *common.Session, dsnConfig msdsn.Config) (*mssql.Connector, error) {
	kc, err := c.getKerberosClient(ctx, sessionCtx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	dbAuth, err := c.getAuth(sessionCtx, kc)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return mssql.NewConnectorConfig(dsnConfig, dbAuth), nil
}

// getAzureConnector generates a connector that authenticates using Azure AD.
func (c *connector) getAzureConnector(ctx context.Context, sessionCtx *common.Session, dsnConfig msdsn.Config) (*mssql.Connector, error) {
	managedIdentityID, err := c.DBAuth.GetAzureIdentityResourceID(ctx, sessionCtx.DatabaseUser)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	dsnConfig.Parameters = map[string]string{
		FederatedAuthDSNKey: azuread.ActiveDirectoryManagedIdentity,
		ResourceIDDSNKey:    managedIdentityID,
	}

	connector, err := azuread.NewConnectorFromConfig(dsnConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return connector, nil
}

// getAccessTokenConnector generates a connector that uses a token to
// authenticate.
func (c *connector) getAccessTokenConnector(ctx context.Context, sessionCtx *common.Session, dsnConfig msdsn.Config) (*mssql.Connector, error) {
	return mssql.NewSecurityTokenConnector(dsnConfig, func(ctx context.Context) (string, error) {
		return c.DBAuth.GetRDSAuthToken(ctx, sessionCtx)
	})
}
