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

package tbot

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/client/webclient"
	"github.com/gravitational/teleport/api/metadata"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/reversetunnelclient"
	"github.com/gravitational/teleport/lib/tbot/bot"
	"github.com/gravitational/teleport/lib/tbot/config"
	"github.com/gravitational/teleport/lib/tbot/identity"
	"github.com/gravitational/teleport/lib/utils"
)

var tracer = otel.Tracer("github.com/gravitational/teleport/lib/tbot")

const componentTBot = "tbot"

type Bot struct {
	cfg     *config.BotConfig
	log     logrus.FieldLogger
	modules modules.Modules

	mu             sync.Mutex
	started        bool
	botIdentitySvc *identityService
}

func New(cfg *config.BotConfig, log logrus.FieldLogger) *Bot {
	if log == nil {
		log = utils.NewLogger()
	}

	return &Bot{
		cfg:     cfg,
		log:     log,
		modules: modules.GetModules(),
	}
}

func (b *Bot) markStarted() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.started {
		return trace.BadParameter("bot has already been started")
	}
	b.started = true

	return nil
}

type getBotIdentityFn func() *identity.Identity

// BotIdentity returns the bot's own identity. This will return nil if the bot
// has not been started.
func (b *Bot) BotIdentity() *identity.Identity {
	return b.botIdentitySvc.GetIdentity()
}

func (b *Bot) Run(ctx context.Context) error {
	ctx, span := tracer.Start(ctx, "Bot/Run")
	defer span.End()

	if err := b.markStarted(); err != nil {
		return trace.Wrap(err)
	}
	unlock, err := b.preRunChecks(ctx)
	defer func() {
		b.log.Debug("Unlocking bot storage.")
		if unlock != nil {
			if err := unlock(); err != nil {
				b.log.WithError(err).Warn("Failed to release lock. Future starts of tbot may fail.")
			}
		}
	}()
	if err != nil {
		return trace.Wrap(err)
	}

	resolver, err := reversetunnelclient.CachingResolver(
		ctx,
		reversetunnelclient.WebClientResolver(&webclient.Config{
			Context:   ctx,
			ProxyAddr: b.cfg.AuthServer,
			Insecure:  b.cfg.Insecure,
		}),
		nil /* clock */)
	if err != nil {
		return trace.Wrap(err)
	}

	// Create an error group to manage all the services lifetimes.
	eg, egCtx := errgroup.WithContext(ctx)
	var services []bot.Service

	// ReloadBroadcaster allows multiple entities to trigger a reload of
	// all services. This allows os signals and other events such as CA
	// rotations to trigger appropriate renewals.
	reloadBroadcaster := &channelBroadcaster{
		chanSet: map[chan struct{}]struct{}{},
	}
	// Trigger reloads from an configured reload channel.
	if b.cfg.ReloadCh != nil {
		// We specifically do not use the error group here as we do not want
		// this goroutine to block the bot from exiting.
		go func() {
			for {
				select {
				case <-egCtx.Done():
					return
				case <-b.cfg.ReloadCh:
					reloadBroadcaster.broadcast()
				}
			}
		}()
	}

	b.botIdentitySvc = &identityService{
		cfg:               b.cfg,
		reloadBroadcaster: reloadBroadcaster,
		resolver:          resolver,
		log: b.log.WithField(
			trace.Component, teleport.Component(componentTBot, "identity"),
		),
	}
	// Initialize bot's own identity. This will load from disk, or fetch a new
	// identity, and perform an initial renewal if necessary.
	if err := b.botIdentitySvc.Initialize(ctx); err != nil {
		return trace.Wrap(err)
	}
	defer func() {
		if err := b.botIdentitySvc.Close(); err != nil {
			b.log.WithError(err).Error("Failed to close bot identity service")
		}
	}()
	services = append(services, b.botIdentitySvc)

	// Setup all other services
	if b.cfg.DiagAddr != "" {
		services = append(services, &diagnosticsService{
			diagAddr:     b.cfg.DiagAddr,
			pprofEnabled: b.cfg.Debug,
			log: b.log.WithField(
				trace.Component, teleport.Component(componentTBot, "diagnostics"),
			),
		})
	}
	services = append(services, &outputsService{
		getBotIdentity: b.botIdentitySvc.GetIdentity,
		botClient:      b.botIdentitySvc.GetClient(),
		cfg:            b.cfg,
		resolver:       resolver,
		log: b.log.WithField(
			trace.Component, teleport.Component(componentTBot, "outputs"),
		),
		reloadBroadcaster: reloadBroadcaster,
	})
	services = append(services, &caRotationService{
		getBotIdentity: b.botIdentitySvc.GetIdentity,
		botClient:      b.botIdentitySvc.GetClient(),
		log: b.log.WithField(
			trace.Component, teleport.Component(componentTBot, "ca-rotation"),
		),
		reloadBroadcaster: reloadBroadcaster,
	})
	// Append any services configured by the user
	services = append(services, b.cfg.Services...)

	b.log.Info("Initialization complete. Starting services.")
	// Start services
	for _, svc := range services {
		svc := svc
		log := b.log.WithField("service", svc.String())

		if b.cfg.Oneshot {
			svc, ok := svc.(bot.OneShotService)
			// We ignore services with no one-shot implementation
			if !ok {
				log.Debug("Service does not support oneshot mode, ignoring.")
				continue
			}
			eg.Go(func() error {
				log.Info("Running service in oneshot mode.")
				err := svc.OneShot(egCtx)
				if err != nil {
					log.WithError(err).Error("Service exited with error.")
					return trace.Wrap(err, "service(%s)", svc.String())
				}
				log.Info("Service finished.")
				return nil
			})
		} else {
			eg.Go(func() error {
				log.Info("Starting service.")
				err := svc.Run(egCtx)
				if err != nil {
					log.WithError(err).Error("Service exited with error.")
					return trace.Wrap(err, "service(%s)", svc.String())
				}
				log.Info("Service exited.")
				return nil
			})
		}
	}

	return eg.Wait()
}

// preRunChecks returns an unlock function which must be deferred.
// It performs any initial validation and locks the bot's storage before any
// more expensive initialization is performed.
func (b *Bot) preRunChecks(ctx context.Context) (func() error, error) {
	ctx, span := tracer.Start(ctx, "Bot/preRunChecks")
	defer span.End()

	switch _, addrKind := b.cfg.Address(); addrKind {
	case config.AddressKindUnspecified:
		return nil, trace.BadParameter(
			"either a proxy or auth address must be set using --proxy, --auth-server or configuration",
		)
	}

	// Ensure they have provided a join method.
	if b.cfg.Onboarding.JoinMethod == types.JoinMethodUnspecified {
		return nil, trace.BadParameter("join method must be provided")
	}

	if b.cfg.FIPS {
		if !b.modules.IsBoringBinary() {
			b.log.Error("FIPS mode enabled but FIPS compatible binary not in use. Ensure you are using the Enterprise FIPS binary to use this flag.")
			return nil, trace.BadParameter("fips mode enabled but binary was not compiled with boringcrypto")
		}
		b.log.Info("Bot is running in FIPS compliant mode.")
	}

	// First, try to make sure all destinations are usable.
	if err := checkDestinations(ctx, b.cfg); err != nil {
		return nil, trace.Wrap(err)
	}

	// Start by loading the bot's primary storage.
	store := b.cfg.Storage.Destination
	if err := identity.VerifyWrite(ctx, store); err != nil {
		return nil, trace.Wrap(
			err, "Could not write to destination %s, aborting", store,
		)
	}

	// Now attempt to lock the destination so we have sole use of it
	unlock, err := store.TryLock()
	if err != nil {
		if errors.Is(err, utils.ErrUnsuccessfulLockTry) {
			return unlock, trace.Wrap(
				err,
				"Failed to acquire exclusive lock for tbot destination directory - is tbot already running?",
			)
		}
		return unlock, trace.Wrap(err)
	}

	return unlock, nil
}

// checkDestinations checks all destinations and tries to create any that
// don't already exist.
func checkDestinations(ctx context.Context, cfg *config.BotConfig) error {
	// Note: This is vaguely problematic as we don't recommend that users
	// store renewable certs under the same user as end-user certs. That said,
	//  - if the destination was properly created via tbot init this is a no-op
	//  - if users intend to follow that advice but miss a step, it should fail
	//    due to lack of permissions
	storageDest := cfg.Storage.Destination

	// Note: no subdirs to init for bot's internal storage.
	if err := storageDest.Init(ctx, []string{}); err != nil {
		return trace.Wrap(err)
	}

	// TODO: consider warning if ownership of all destinations is not expected.
	for _, output := range cfg.Outputs {
		if err := output.Init(ctx); err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}

// checkIdentity performs basic startup checks on an identity and loudly warns
// end users if it is unlikely to work.
func checkIdentity(log logrus.FieldLogger, ident *identity.Identity) error {
	var validAfter time.Time
	var validBefore time.Time

	if ident.X509Cert != nil {
		validAfter = ident.X509Cert.NotBefore
		validBefore = ident.X509Cert.NotAfter
	} else if ident.SSHCert != nil {
		validAfter = time.Unix(int64(ident.SSHCert.ValidAfter), 0)
		validBefore = time.Unix(int64(ident.SSHCert.ValidBefore), 0)
	} else {
		return trace.BadParameter("identity is invalid and contains no certificates")
	}

	now := time.Now().UTC()
	if now.After(validBefore) {
		log.Errorf(
			"Identity has expired. The renewal is likely to fail. (expires: %s, current time: %s)",
			validBefore.Format(time.RFC3339),
			now.Format(time.RFC3339),
		)
	} else if now.Before(validAfter) {
		log.Warnf(
			"Identity is not yet valid. Confirm that the system time is correct. (valid after: %s, current time: %s)",
			validAfter.Format(time.RFC3339),
			now.Format(time.RFC3339),
		)
	}

	return nil
}

// clientForFacade creates a new auth client from the given
// facade. Note that depending on the connection address given, this may
// attempt to connect via the proxy and therefore requires both SSH and TLS
// credentials.
func clientForFacade(
	ctx context.Context,
	log logrus.FieldLogger,
	cfg *config.BotConfig,
	facade *identity.Facade,
	resolver reversetunnelclient.Resolver,
) (auth.ClientI, error) {
	ctx, span := tracer.Start(ctx, "clientForFacade")
	defer span.End()

	tlsConfig, err := facade.TLSConfig()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	sshConfig, err := facade.SSHClientConfig()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	addr, _ := cfg.Address()
	parsedAddr, err := utils.ParseAddr(addr)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	authClientConfig := &authclient.Config{
		TLS:         tlsConfig,
		SSH:         sshConfig,
		AuthServers: []utils.NetAddr{*parsedAddr},
		Log:         log,
		Insecure:    cfg.Insecure,
		Resolver:    resolver,
		DialOpts:    []grpc.DialOption{metadata.WithUserAgentFromTeleportComponent(teleport.ComponentTBot)},
	}

	c, err := authclient.Connect(ctx, authClientConfig)
	return c, trace.Wrap(err)
}
