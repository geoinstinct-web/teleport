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

const (
	// MySQLPort is the Azure managed MySQL server port
	// https://docs.microsoft.com/en-us/azure/mysql/single-server/concepts-connectivity-architecture
	MySQLPort = "3306"
	// PostgresPort is the Azure managed PostgreSQL server port
	// https://docs.microsoft.com/en-us/azure/postgresql/single-server/concepts-connectivity-architecture
	PostgresPort = "5432"
	// resourceOwner is used to identify who owns the ClusterRole and ClusterRoleBinding.
	resourceOwner = "Teleport"
)
