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

package sidecar

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/tbot"
	"github.com/gravitational/teleport/lib/tbot/config"
	"github.com/gravitational/teleport/lib/tbot/identity"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"
)

const (
	DefaultCertificateTTL  = 2 * time.Hour
	DefaultRenewalInterval = 30 * time.Minute
)

// Bot is a wrapper around an embedded tbot.
// It implements sigs.k8s.io/controller-runtime/manager.Runnable and
// sigs.k8s.io/controller-runtime/manager.LeaderElectionRunnable so it can be added to a controllerruntime.Manager.
type Bot struct {
	cfg        *config.BotConfig
	running    bool
	rootClient auth.ClientI
	opts       Options

	// mutex protects cachedCert and cachedClient
	mutex        sync.Mutex
	cachedCert   []byte
	cachedClient *SyncClient

	// clientBuilder is used for testing purposes. Outside of tests, its value should always be buildClient.
	clientBuilder func(ctx context.Context) (*SyncClient, error)
}

func (b *Bot) initializeConfig() {
	// Initialize the memory stores. They contain identities renewed by the bot
	// We're reading certs directly from them
	rootMemoryStore := &config.DestinationMemory{}
	destMemoryStore := &config.DestinationMemory{}

	// Initialize tbot config
	b.cfg = &config.BotConfig{
		Onboarding: &config.OnboardingConfig{
			TokenValue: "",         // Field should be populated later, before running
			CAPins:     []string{}, // Field should be populated later, before running
			JoinMethod: types.JoinMethodToken,
		},
		Storage: &config.StorageConfig{
			DestinationMixin: config.DestinationMixin{
				Memory: rootMemoryStore,
			},
		},
		Destinations: []*config.DestinationConfig{
			{
				DestinationMixin: config.DestinationMixin{
					Memory: destMemoryStore,
				},
			},
		},
		Debug:           false,
		AuthServer:      b.opts.Addr,
		CertificateTTL:  DefaultCertificateTTL,
		RenewalInterval: DefaultRenewalInterval,
		Oneshot:         false,
	}

	// We do our own init because config's "CheckAndSetDefaults" is too linked with tbot logic and invokes
	// `addRequiredConfigs` on each Storage Destination
	rootMemoryStore.CheckAndSetDefaults()
	destMemoryStore.CheckAndSetDefaults()

	for _, artifact := range identity.GetArtifacts() {
		_ = destMemoryStore.Write(artifact.Key, []byte{})
		_ = rootMemoryStore.Write(artifact.Key, []byte{})
	}

}

// buildClient reads tbot's memory disttination, retrieves the certificates
// and builds a new Teleport client using those certs.
func (b *Bot) buildClient(ctx context.Context) (*SyncClient, error) {
	log.Infof("Building a new client to connect to %s", b.cfg.AuthServer)

	// Hack to be able to reuse LoadIdentity functions from tbot
	// LoadIdentity expects to have all the artifacts required for a bot
	// We loop over missing artifacts and are loading them from the bot storage to the destination
	for _, artifact := range identity.GetArtifacts() {
		if artifact.Kind == identity.KindBotInternal {
			value, err := b.cfg.Storage.Memory.Read(artifact.Key)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			if err := b.cfg.Destinations[0].Memory.Write(artifact.Key, value); err != nil {
				return nil, trace.Wrap(err)
			}

		}
	}

	id, err := identity.LoadIdentity(b.cfg.Destinations[0].Memory, identity.BotKinds()...)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	c, err := client.New(ctx, client.Config{
		Addrs:       []string{b.cfg.AuthServer},
		Credentials: []client.Credentials{clientCredentials{id}},
	})
	return NewSyncClient(c), trace.Wrap(err)
}

// GetSyncClient gets a client authenticated as the bot. To avoid rebuilding a
// client for each call, this function caches the client and creates a new one
// only when the client certs changed (tbot renewed them).
func (b *Bot) GetSyncClient(ctx context.Context) (*SyncClient, func(), error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if !b.running {
		return nil, nil, trace.Errorf("bot not started yet")
	}
	// If the bot has not joined the cluster yet or not generated client certs we bail out
	// This is either temporary or the bot is dead and the manager will shut down everything.
	storageDestination := b.cfg.Storage.Memory
	if botCert, err := storageDestination.Read(identity.TLSCertKey); err != nil || len(botCert) == 0 {
		return nil, nil, trace.Retry(err, "bot cert not yet present")
	}

	cert, err := b.cfg.Destinations[0].Memory.Read(identity.TLSCertKey)
	if err != nil || len(cert) == 0 {
		return nil, nil, trace.Retry(err, "cert not yet present")
	}

	// This is where caching happens. We don't know when tbot renews the certificates, so we need to check
	// if the current certificate stored in memory changed since last time. If it did not and we already built a
	// working client, then we hit the cache. Else we build a new client, replace the cached client with the new one,
	// and fire a separate goroutine to close the previous client.
	if b.cachedClient != nil && bytes.Equal(cert, b.cachedCert) {
		return b.cachedClient, b.cachedClient.LockClient(), nil
	}

	oldClient := b.cachedClient
	freshClient, err := b.clientBuilder(ctx)

	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	b.cachedCert = cert
	b.cachedClient = freshClient

	if oldClient != nil {
		go oldClient.RetireClient()
	}

	return b.cachedClient, b.cachedClient.LockClient(), nil
}

type clientCredentials struct {
	id *identity.Identity
}

func (c clientCredentials) Dialer(client.Config) (client.ContextDialer, error) {
	return nil, trace.NotImplemented("no dialer")
}

func (c clientCredentials) TLSConfig() (*tls.Config, error) {
	return c.id.TLSConfig(utils.DefaultCipherSuites())
}

func (c clientCredentials) SSHClientConfig() (*ssh.ClientConfig, error) {
	return c.id.SSHClientConfig(false)
}

func (b *Bot) NeedLeaderElection() bool {
	return true
}

func (b *Bot) Start(ctx context.Context) error {
	token, err := createOrReplaceBot(ctx, b.opts, b.rootClient)
	if err != nil {
		return trace.Wrap(err)
	}
	log.Infof("Token generated %s", token)

	b.cfg.Onboarding.TokenValue = token

	// Getting the cluster CA Pins to be able to join regardless of the cert SANs.
	localCAResponse, err := b.rootClient.GetClusterCACert(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	caPins, err := tlsca.CalculatePins(localCAResponse.TLSCA)
	if err != nil {
		return trace.Wrap(err)
	}
	log.Infof("CA Pins recovered: %s", caPins)

	b.cfg.Onboarding.CAPins = caPins

	reloadChan := make(chan struct{})
	realBot := tbot.New(b.cfg, log.StandardLogger(), reloadChan)

	b.running = true
	log.Info("Running tbot")
	return trace.Wrap(realBot.Run(ctx))
}

// CreateAndBootstrapBot connects to teleport using a local auth connection, creates operator's role in teleport
// and creates tbot's configuration.
func CreateAndBootstrapBot(ctx context.Context, opts Options) (*Bot, *proto.Features, error) {
	if err := opts.CheckAndSetDefaults(); err != nil {
		return nil, nil, trace.Wrap(err)
	}

	// First we are creating a local auth client, like local tctl
	authClientConfig, err := createAuthClientConfig(opts)
	if err != nil {
		return nil, nil, trace.WrapWithMessage(err, "failed to create auth client config")
	}

	authClient, err := authclient.Connect(ctx, authClientConfig)
	if err != nil {
		return nil, nil, trace.WrapWithMessage(err, "failed to create auth client")
	}

	ping, err := authClient.Ping(ctx)
	if err != nil {
		return nil, nil, trace.WrapWithMessage(err, "failed to ping teleport")
	}

	// Then we create a role for the operator
	role, err := sidecarRole(opts.Role)
	if err != nil {
		return nil, nil, trace.WrapWithMessage(err, "failed to create role")
	}

	if err := authClient.UpsertRole(ctx, role); err != nil {
		return nil, nil, trace.WrapWithMessage(err, "failed to create operator's role")
	}
	log.Debug("Operator role created")

	bot := &Bot{
		running:    false,
		rootClient: authClient,
		opts:       opts,
	}

	bot.clientBuilder = bot.buildClient
	bot.initializeConfig()

	return bot, ping.ServerFeatures, nil
}

// It is not currently possible to join back the cluster as an existing bot.
// See https://github.com/gravitational/teleport/issues/13091
func createOrReplaceBot(ctx context.Context, opts Options, authClient auth.ClientI) (string, error) {
	var token string
	// We need to check if the bot exists first and cannot just attempt to delete
	// it because DeleteBot() returns an aggregate, which breaks the
	// ToGRPC/FromGRPC status code translation. We end up with the wrong error
	// type and cannot check if `trace.IsNotFound()`
	botRoleName := fmt.Sprintf("bot-%s", opts.Name)
	exists, err := botExists(ctx, opts, authClient)
	if err != nil {
		return "", trace.Wrap(err)
	}
	if exists {
		err := authClient.DeleteBot(ctx, opts.Name)
		if err != nil {
			return "", trace.Wrap(err)
		}
	}
	if err := authClient.DeleteRole(ctx, botRoleName); err != nil && !trace.IsNotFound(err) {
		return "", trace.Wrap(err)
	}
	response, err := authClient.CreateBot(ctx, &proto.CreateBotRequest{
		Name:  opts.Name,
		Roles: []string{opts.Role},
	})
	if err != nil {
		return "", trace.Wrap(err)
	}
	token = response.TokenID

	return token, nil
}

func botExists(ctx context.Context, opts Options, authClient auth.ClientI) (bool, error) {
	botUsers, err := authClient.GetBotUsers(ctx)
	if err != nil {
		return false, trace.Wrap(err)
	}
	for _, botUser := range botUsers {
		if botUser.GetName() == fmt.Sprintf("bot-%s", opts.Name) {
			return true, nil
		}
	}
	return false, nil
}
