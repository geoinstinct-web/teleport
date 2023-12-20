/*
Copyright 2023 Gravitational, Inc.

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

package discovery

import (
	"context"
	"sync"
	"time"

	"github.com/gravitational/trace"

	usageeventsv1 "github.com/gravitational/teleport/api/gen/proto/go/usageevents/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv/discovery/common"
	"github.com/gravitational/teleport/lib/utils"
)

const appEventPrefix = "app/"

func (s *Server) startKubeAppsWatchers() error {
	if len(s.kubeAppsFetchers) == 0 {
		return nil
	}

	var (
		appResources []types.Application
		mu           sync.Mutex
	)

	reconciler, err := services.NewReconciler(
		services.ReconcilerConfig[types.Application]{
			Matcher: func(_ types.Application) bool { return true },
			GetCurrentResources: func() map[string]types.Application {
				apps, err := s.AccessPoint.GetApps(s.ctx)
				if err != nil {
					s.Log.WithError(err).Warn("Unable to get applications from cache.")
					return nil
				}

				return utils.FromSlice(filterResources(apps, types.OriginDiscoveryKubernetes, s.DiscoveryGroup), types.Application.GetName)
			},
			GetNewResources: func() map[string]types.Application {
				mu.Lock()
				defer mu.Unlock()
				return utils.FromSlice(appResources, types.Application.GetName)
			},
			Log:      s.Log.WithField("kind", types.KindApp),
			OnCreate: s.onAppCreate,
			OnUpdate: s.onAppUpdate,
			OnDelete: s.onAppDelete,
		},
	)
	if err != nil {
		return trace.Wrap(err)
	}

	watcher, err := common.NewWatcher(s.ctx, common.WatcherConfig{
		FetchersFn:     common.StaticFetchers(s.kubeAppsFetchers),
		Interval:       5 * time.Minute,
		Log:            s.Log.WithField("kind", types.KindApp),
		DiscoveryGroup: s.DiscoveryGroup,
		Origin:         types.OriginDiscoveryKubernetes,
	})
	if err != nil {
		return trace.Wrap(err)
	}
	go watcher.Start()

	go func() {
		for {
			select {
			case newResources := <-watcher.ResourcesC():
				apps := make([]types.Application, 0, len(newResources))
				for _, r := range newResources {
					app, ok := r.(types.Application)
					if !ok {
						continue
					}

					apps = append(apps, app)
				}

				mu.Lock()
				appResources = apps
				mu.Unlock()

				if err := reconciler.Reconcile(s.ctx); err != nil {
					s.Log.WithError(err).Warn("Unable to reconcile resources.")
				}

			case <-s.ctx.Done():
				return
			}
		}
	}()
	return nil
}

func (s *Server) onAppCreate(ctx context.Context, app types.Application) error {
	s.Log.Debugf("Creating app %s", app.GetName())
	err := s.AccessPoint.CreateApp(ctx, app)
	// If the resource already exists, it means that the resource was created
	// by a previous discovery_service instance that didn't support the discovery
	// group feature or the discovery group was changed.
	// In this case, we need to update the resource with the
	// discovery group label to ensure the user doesn't have to manually delete
	// the resource.
	if trace.IsAlreadyExists(err) {
		return trace.Wrap(s.onAppUpdate(ctx, app))
	}
	if err != nil {
		return trace.Wrap(err)
	}
	err = s.emitUsageEvents(map[string]*usageeventsv1.ResourceCreateEvent{
		appEventPrefix + app.GetName(): {
			ResourceType:   types.DiscoveredResourceApp,
			ResourceOrigin: types.OriginKubernetes,
			// CloudProvider is not set for apps created from Kubernetes services
		},
	})
	if err != nil {
		s.Log.WithError(err).Debug("Error emitting usage event.")
	}
	return nil
}

func (s *Server) onAppUpdate(ctx context.Context, app types.Application) error {
	s.Log.Debugf("Updating app %s.", app.GetName())
	return trace.Wrap(s.AccessPoint.UpdateApp(ctx, app))
}

func (s *Server) onAppDelete(ctx context.Context, app types.Application) error {
	s.Log.Debugf("Deleting app %s.", app.GetName())
	return trace.Wrap(s.AccessPoint.DeleteApp(ctx, app.GetName()))
}
