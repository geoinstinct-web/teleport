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

package service

import (
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/srv/discovery"
)

func (process *TeleportProcess) shouldInitDiscovery() bool {
	return process.Config.Discovery.Enabled && !process.Config.Discovery.IsEmpty()
}

func (process *TeleportProcess) initDiscovery() {
	process.RegisterWithAuthServer(types.RoleDiscovery, DiscoveryIdentityEvent)
	process.RegisterCriticalFunc("discovery.init", process.initDiscoveryService)
}

func (process *TeleportProcess) initDiscoveryService() error {
	log := process.log.WithField(trace.Component, teleport.Component(
		teleport.ComponentDiscovery, process.id))

	conn, err := process.WaitForConnector(DiscoveryIdentityEvent, log)
	if conn == nil {
		return trace.Wrap(err)
	}

	accessPoint, err := process.newLocalCacheForDiscovery(conn.Client,
		[]string{teleport.ComponentDiscovery})
	if err != nil {
		return trace.Wrap(err)
	}

	// asyncEmitter makes sure that sessions do not block
	// in case if connections are slow
	asyncEmitter, err := process.NewAsyncEmitter(conn.Client)
	if err != nil {
		return trace.Wrap(err)
	}
	// tlsConfig is the DiscoveryService's TLS certificate signed by the cluster's
	// Host certificate authority.
	// It is used to authenticate the DiscoveryService to the Access Graph service.
	tlsConfig, err := conn.ServerIdentity.TLSConfig(process.Config.CipherSuites)
	if err != nil {
		return trace.Wrap(err)
	}

	discoveryService, err := discovery.New(process.ExitContext(), &discovery.Config{
		IntegrationOnlyCredentials: process.integrationOnlyCredentials(),
		Matchers: discovery.Matchers{
			AWS:         process.Config.Discovery.AWSMatchers,
			Azure:       process.Config.Discovery.AzureMatchers,
			GCP:         process.Config.Discovery.GCPMatchers,
			Kubernetes:  process.Config.Discovery.KubernetesMatchers,
			AccessGraph: process.Config.Discovery.AccessGraph,
		},
		DiscoveryGroup:    process.Config.Discovery.DiscoveryGroup,
		Emitter:           asyncEmitter,
		AccessPoint:       accessPoint,
		Log:               process.log,
		ClusterName:       conn.ClientIdentity.ClusterName,
		PollInterval:      process.Config.Discovery.PollInterval,
		ServerCredentials: tlsConfig,
		AccessGraphConfig: process.Config.AccessGraph,
	})
	if err != nil {
		return trace.Wrap(err)
	}

	process.OnExit("discovery.stop", func(payload interface{}) {
		log.Info("Shutting down.")
		if discoveryService != nil {
			discoveryService.Stop()
		}
		if asyncEmitter != nil {
			warnOnErr(asyncEmitter.Close(), process.log)
		}
		warnOnErr(conn.Close(), log)
		log.Info("Exited.")
	})

	process.BroadcastEvent(Event{Name: DiscoveryReady, Payload: nil})

	if err := discoveryService.Start(); err != nil {
		return trace.Wrap(err)
	}
	log.Infof("Discovery service has successfully started")

	if err := discoveryService.Wait(); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// integrationOnlyCredentials indicates whether the DiscoveryService must only use Cloud APIs credentials using an integration.
//
// If Auth is running alongside this DiscoveryService and License is Cloud, then this process is running in Teleport's Cloud Infra.
// In those situations, ambient credentials (used by the AWS SDK) will provide access to the tenant's infra, which is not desired.
// Setting IntegrationOnlyCredentials to true, will prevent usage of the ambient credentials.
func (process *TeleportProcess) integrationOnlyCredentials() bool {
	return process.Config.Auth.Enabled && modules.GetModules().Features().Cloud
}
