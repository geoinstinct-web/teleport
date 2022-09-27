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

package azure

import (
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresql"
	log "github.com/sirupsen/logrus"

	"github.com/gravitational/teleport/lib/defaults"
)

// DBServer represents an Azure DB Server.
// It exists to reduce code duplication, since Azure MySQL and PostgreSQL
// server fields are identical in all but type.
// TODO(gavin): Remove this in favor of generics when Go supports structural constraints
// on generic types.
type DBServer struct {
	// ID is the fully qualified resource ID for this resource.
	ID string
	// Location is the geo-location where the resource lives.
	Location string
	// Name is the name of the resource.
	Name string
	// Port is the port used to connect to this resource.
	Port string
	// Properties contains properties for an DB Server.
	Properties ServerProperties
	// Protocol is the DB protocol used for this DB Server.
	Protocol string
	// Tags are the resource tags associated with this resource.
	Tags map[string]string
}

// ServerProperties contains properties for an DB Server.
type ServerProperties struct {
	// FullyQualifiedDomainName is the fully qualified domain name which resolves to the DB Server address.
	FullyQualifiedDomainName string
	// UserVisibleState is the state of the DB Server that is visible to a user.
	UserVisibleState string
	// Version is the version of the Azure gateway which redirects traffic to the database servers.
	Version string
}

// ServerFromMySQLServer converts an Azure armmysql.Server into DBServer.
func ServerFromMySQLServer(server *armmysql.Server) *DBServer {
	result := &DBServer{
		ID:       StringVal(server.ID),
		Location: StringVal(server.Location),
		Name:     StringVal(server.Name),
		Port:     MySQLPort,
		Protocol: defaults.ProtocolMySQL,
		Tags:     ToMapOfString(server.Tags),
	}
	if server.Properties != nil {
		result.Properties = ServerProperties{
			FullyQualifiedDomainName: StringVal(server.Properties.FullyQualifiedDomainName),
			UserVisibleState:         StringVal(server.Properties.UserVisibleState),
			Version:                  StringVal(server.Properties.Version),
		}
	}
	return result
}

// ServerFromPostgresServer converts an Azure armpostgresql.Server into DBServer.
func ServerFromPostgresServer(server *armpostgresql.Server) *DBServer {
	result := &DBServer{
		ID:       StringVal(server.ID),
		Location: StringVal(server.Location),
		Name:     StringVal(server.Name),
		Port:     PostgresPort,
		Protocol: defaults.ProtocolPostgres,
		Tags:     ToMapOfString(server.Tags),
	}
	if server.Properties != nil {
		result.Properties = ServerProperties{
			FullyQualifiedDomainName: StringVal(server.Properties.FullyQualifiedDomainName),
			UserVisibleState:         StringVal(server.Properties.UserVisibleState),
			Version:                  StringVal(server.Properties.Version),
		}
	}
	return result
}

// IsSupported returns true if database supports AAD authentication.
// Only available for MySQL 5.7 and newer. All Azure managed PostgreSQL single-server
// instances support AAD auth.
func (s *DBServer) IsSupported() bool {
	switch s.Protocol {
	case defaults.ProtocolMySQL:
		return isMySQLVersionSupported(s)
	case defaults.ProtocolPostgres:
		return isPostgresVersionSupported(s)
	default:
		return false
	}
}

// IsAvailable returns whether the Azure DBServer is available.
func (s *DBServer) IsAvailable() bool {
	switch s.Properties.UserVisibleState {
	case "Ready":
		return true
	case "Inaccessible", "Dropping", "Disabled":
		return false
	default:
		log.Warnf("Unknown server state: %q. Assuming Azure DB server %q is available.",
			s.Properties.UserVisibleState,
			s.Name,
		)
		return true
	}
}
