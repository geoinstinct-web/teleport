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

package services

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/bufbuild/connect-go"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	usageevents "github.com/gravitational/teleport/api/gen/proto/go/usageevents/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/observability/metrics"
	prehogv1 "github.com/gravitational/teleport/lib/prehog/gen/prehog/v1alpha"
	prehogclient "github.com/gravitational/teleport/lib/prehog/gen/prehog/v1alpha/prehogv1alphaconnect"
	"github.com/gravitational/teleport/lib/usagereporter"
	"github.com/gravitational/teleport/lib/utils"
)

const (
	// usageReporterMinBatchSize determines the size at which a batch is sent
	// regardless of elapsed time
	usageReporterMinBatchSize = 20

	// usageReporterMaxBatchSize is the largest batch size that will be sent to
	// the server; batches larger than this will be split into multiple
	// requests.
	usageReporterMaxBatchSize = 100

	// usageReporterMaxBatchAge is the maximum age a batch may reach before
	// being flushed, regardless of the batch size
	usageReporterMaxBatchAge = time.Second * 5

	// usageReporterMaxBufferSize is the maximum size to which the event buffer
	// may grow. Events submitted once this limit is reached will be discarded.
	// Events that were in the submission queue that fail to submit may also be
	// discarded when requeued.
	usageReporterMaxBufferSize = 500

	// usageReporterSubmitDelay is a mandatory delay added to each batch submission
	// to avoid spamming the prehog instance.
	usageReporterSubmitDelay = time.Second * 1

	// usageReporterRetryAttempts is the max number of attempts that
	// should be made to submit a particular event before it's dropped
	usageReporterRetryAttempts = 5
)

// UsageAnonymizable is an event that can be anonymized.
type UsageAnonymizable interface {
	// Anonymize uses the given anonymizer to anonymize the event and converts
	// it into a partially filled SubmitEventRequest.
	Anonymize(utils.Anonymizer) prehogv1.SubmitEventRequest
}

// UsageReporter is a service that accepts Teleport usage events.
type UsageReporter interface {
	// AnonymizeAndSubmit submits a usage event. The payload will be
	// anonymized by the reporter implementation.
	AnonymizeAndSubmit(event ...UsageAnonymizable) error
}

// UsageUserLogin is an event emitted when a user logs into Teleport,
// potentially via SSO.
type UsageUserLogin prehogv1.UserLoginEvent

func (u *UsageUserLogin) Anonymize(a utils.Anonymizer) prehogv1.SubmitEventRequest {
	return prehogv1.SubmitEventRequest{
		Event: &prehogv1.SubmitEventRequest_UserLogin{
			UserLogin: &prehogv1.UserLoginEvent{
				UserName:      a.AnonymizeString(u.UserName),
				ConnectorType: u.ConnectorType,
			},
		},
	}
}

// UsageSSOCreate is emitted when an SSO connector has been created.
type UsageSSOCreate prehogv1.SSOCreateEvent

func (u *UsageSSOCreate) Anonymize(a utils.Anonymizer) prehogv1.SubmitEventRequest {
	return prehogv1.SubmitEventRequest{
		Event: &prehogv1.SubmitEventRequest_SsoCreate{
			SsoCreate: &prehogv1.SSOCreateEvent{
				ConnectorType: u.ConnectorType,
			},
		},
	}
}

// UsageSessionStart is an event emitted when some Teleport session has started
// (ssh, etc).
type UsageSessionStart prehogv1.SessionStartEvent

func (u *UsageSessionStart) Anonymize(a utils.Anonymizer) prehogv1.SubmitEventRequest {
	return prehogv1.SubmitEventRequest{
		Event: &prehogv1.SubmitEventRequest_SessionStartV2{
			SessionStartV2: &prehogv1.SessionStartEvent{
				UserName:    a.AnonymizeString(u.UserName),
				SessionType: u.SessionType,
			},
		},
	}
}

// UsageResourceCreate is an event emitted when various resource types have been
// created.
type UsageResourceCreate prehogv1.ResourceCreateEvent

func (u *UsageResourceCreate) Anonymize(a utils.Anonymizer) prehogv1.SubmitEventRequest {
	return prehogv1.SubmitEventRequest{
		Event: &prehogv1.SubmitEventRequest_ResourceCreate{
			ResourceCreate: &prehogv1.ResourceCreateEvent{
				ResourceType: u.ResourceType,
			},
		},
	}
}

// UsageUIBannerClick is a UI event sent when a banner is clicked.
type UsageUIBannerClick prehogv1.UIBannerClickEvent

func (u *UsageUIBannerClick) Anonymize(a utils.Anonymizer) prehogv1.SubmitEventRequest {
	return prehogv1.SubmitEventRequest{
		Event: &prehogv1.SubmitEventRequest_UiBannerClick{
			UiBannerClick: &prehogv1.UIBannerClickEvent{
				UserName: a.AnonymizeString(u.UserName),
				Alert:    u.Alert,
			},
		},
	}
}

// UsageUIOnboardCompleteGoToDashboardClickEvent is a UI event sent when
// onboarding is complete.
type UsageUIOnboardCompleteGoToDashboardClickEvent prehogv1.UIOnboardCompleteGoToDashboardClickEvent

func (u *UsageUIOnboardCompleteGoToDashboardClickEvent) Anonymize(a utils.Anonymizer) prehogv1.SubmitEventRequest {
	return prehogv1.SubmitEventRequest{
		Event: &prehogv1.SubmitEventRequest_UiOnboardCompleteGoToDashboardClick{
			UiOnboardCompleteGoToDashboardClick: &prehogv1.UIOnboardCompleteGoToDashboardClickEvent{
				UserName: a.AnonymizeString(u.UserName),
			},
		},
	}
}

// UsageUIOnboardAddFirstResourceClickEvent is a UI event sent when a user
// clicks the "add first resource" button.
type UsageUIOnboardAddFirstResourceClickEvent prehogv1.UIOnboardAddFirstResourceClickEvent

func (u *UsageUIOnboardAddFirstResourceClickEvent) Anonymize(a utils.Anonymizer) prehogv1.SubmitEventRequest {
	return prehogv1.SubmitEventRequest{
		Event: &prehogv1.SubmitEventRequest_UiOnboardAddFirstResourceClick{
			UiOnboardAddFirstResourceClick: &prehogv1.UIOnboardAddFirstResourceClickEvent{
				UserName: a.AnonymizeString(u.UserName),
			},
		},
	}
}

// UsageUIOnboardAddFirstResourceLaterClickEvent is a UI event sent when a user
// clicks the "add first resource later" button.
type UsageUIOnboardAddFirstResourceLaterClickEvent prehogv1.UIOnboardAddFirstResourceLaterClickEvent

func (u *UsageUIOnboardAddFirstResourceLaterClickEvent) Anonymize(a utils.Anonymizer) prehogv1.SubmitEventRequest {
	return prehogv1.SubmitEventRequest{
		Event: &prehogv1.SubmitEventRequest_UiOnboardAddFirstResourceLaterClick{
			UiOnboardAddFirstResourceLaterClick: &prehogv1.UIOnboardAddFirstResourceLaterClickEvent{
				UserName: a.AnonymizeString(u.UserName),
			},
		},
	}
}

// UsageUIOnboardSetCredentialSubmit is an UI event sent during registration
// when the user configures login credentials.
type UsageUIOnboardSetCredentialSubmit prehogv1.UIOnboardSetCredentialSubmitEvent

func (u *UsageUIOnboardSetCredentialSubmit) Anonymize(a utils.Anonymizer) prehogv1.SubmitEventRequest {
	return prehogv1.SubmitEventRequest{
		Event: &prehogv1.SubmitEventRequest_UiOnboardSetCredentialSubmit{
			UiOnboardSetCredentialSubmit: &prehogv1.UIOnboardSetCredentialSubmitEvent{
				UserName: a.AnonymizeString(u.UserName),
			},
		},
	}
}

// UsageUIOnboardRegisterChallengeSubmit is a UI event sent during registration
// when the MFA challenge is completed.
type UsageUIOnboardRegisterChallengeSubmit prehogv1.UIOnboardRegisterChallengeSubmitEvent

func (u *UsageUIOnboardRegisterChallengeSubmit) Anonymize(a utils.Anonymizer) prehogv1.SubmitEventRequest {
	return prehogv1.SubmitEventRequest{
		Event: &prehogv1.SubmitEventRequest_UiOnboardRegisterChallengeSubmit{
			UiOnboardRegisterChallengeSubmit: &prehogv1.UIOnboardRegisterChallengeSubmitEvent{
				UserName: a.AnonymizeString(u.UserName),
			},
		},
	}
}

// UsageUIRecoveryCodesContinueClick is a UI event sent when a user configures recovery codes.
type UsageUIRecoveryCodesContinueClick prehogv1.UIRecoveryCodesContinueClickEvent

func (u *UsageUIRecoveryCodesContinueClick) Anonymize(a utils.Anonymizer) prehogv1.SubmitEventRequest {
	return prehogv1.SubmitEventRequest{
		Event: &prehogv1.SubmitEventRequest_UiRecoveryCodesContinueClick{
			UiRecoveryCodesContinueClick: &prehogv1.UIRecoveryCodesContinueClickEvent{
				UserName: a.AnonymizeString(u.UserName),
			},
		},
	}
}

// UsageUIRecoveryCodesCopyClick is a UI event sent when a user copies recovery codes.
type UsageUIRecoveryCodesCopyClick prehogv1.UIRecoveryCodesCopyClickEvent

func (u *UsageUIRecoveryCodesCopyClick) Anonymize(a utils.Anonymizer) prehogv1.SubmitEventRequest {
	return prehogv1.SubmitEventRequest{
		Event: &prehogv1.SubmitEventRequest_UiRecoveryCodesCopyClick{
			UiRecoveryCodesCopyClick: &prehogv1.UIRecoveryCodesCopyClickEvent{
				UserName: a.AnonymizeString(u.UserName),
			},
		},
	}
}

// UsageUIRecoveryCodesPrintClick is a UI event sent when a user prints recovery codes.
type UsageUIRecoveryCodesPrintClick prehogv1.UIRecoveryCodesPrintClickEvent

func (u *UsageUIRecoveryCodesPrintClick) Anonymize(a utils.Anonymizer) prehogv1.SubmitEventRequest {
	return prehogv1.SubmitEventRequest{
		Event: &prehogv1.SubmitEventRequest_UiRecoveryCodesPrintClick{
			UiRecoveryCodesPrintClick: &prehogv1.UIRecoveryCodesPrintClickEvent{
				UserName: a.AnonymizeString(u.UserName),
			},
		},
	}
}

// UsageCertificateIssued is an event emitted when a certificate has been
// issued, used to track the duration and restriction.
type UsageCertificateIssued prehogv1.UserCertificateIssuedEvent

func (u *UsageCertificateIssued) Anonymize(a utils.Anonymizer) prehogv1.SubmitEventRequest {
	return prehogv1.SubmitEventRequest{
		Event: &prehogv1.SubmitEventRequest_UserCertificateIssuedEvent{
			UserCertificateIssuedEvent: &prehogv1.UserCertificateIssuedEvent{
				UserName:        a.AnonymizeString(u.UserName),
				Ttl:             u.Ttl,
				IsBot:           u.IsBot,
				UsageDatabase:   u.UsageDatabase,
				UsageApp:        u.UsageApp,
				UsageKubernetes: u.UsageKubernetes,
				UsageDesktop:    u.UsageDesktop,
			},
		},
	}
}

// ConvertUsageEvent converts a usage event from an API object into an
// anonymizable event. All events that can be submitted externally via the Auth
// API need to be defined here.
func ConvertUsageEvent(event *usageevents.UsageEventOneOf, identityUsername string) (UsageAnonymizable, error) {
	// Note: events (especially pre-registration) that embed a username of their
	// own should generally pass that through rather than using the identity
	// username provided to the function. It may be the username of a Teleport
	// component (e.g. proxy) rather than the end user.

	switch e := event.GetEvent().(type) {
	case *usageevents.UsageEventOneOf_UiBannerClick:
		return &UsageUIBannerClick{
			UserName: identityUsername,
			Alert:    e.UiBannerClick.Alert,
		}, nil
	case *usageevents.UsageEventOneOf_UiOnboardAddFirstResourceClick:
		return &UsageUIOnboardAddFirstResourceClickEvent{
			UserName: identityUsername,
		}, nil
	case *usageevents.UsageEventOneOf_UiOnboardAddFirstResourceLaterClick:
		return &UsageUIOnboardAddFirstResourceLaterClickEvent{
			UserName: identityUsername,
		}, nil
	case *usageevents.UsageEventOneOf_UiOnboardCompleteGoToDashboardClick:
		return &UsageUIOnboardCompleteGoToDashboardClickEvent{
			UserName: e.UiOnboardCompleteGoToDashboardClick.Username,
		}, nil
	case *usageevents.UsageEventOneOf_UiOnboardSetCredentialSubmit:
		return &UsageUIOnboardSetCredentialSubmit{
			UserName: e.UiOnboardSetCredentialSubmit.Username,
		}, nil
	case *usageevents.UsageEventOneOf_UiOnboardRegisterChallengeSubmit:
		return &UsageUIOnboardRegisterChallengeSubmit{
			UserName:  e.UiOnboardRegisterChallengeSubmit.Username,
			MfaType:   e.UiOnboardRegisterChallengeSubmit.MfaType,
			LoginFlow: e.UiOnboardRegisterChallengeSubmit.LoginFlow,
		}, nil
	case *usageevents.UsageEventOneOf_UiRecoveryCodesContinueClick:
		return &UsageUIRecoveryCodesContinueClick{
			UserName: e.UiRecoveryCodesContinueClick.Username,
		}, nil
	case *usageevents.UsageEventOneOf_UiRecoveryCodesCopyClick:
		return &UsageUIRecoveryCodesCopyClick{
			UserName: e.UiRecoveryCodesCopyClick.Username,
		}, nil
	case *usageevents.UsageEventOneOf_UiRecoveryCodesPrintClick:
		return &UsageUIRecoveryCodesPrintClick{
			UserName: e.UiRecoveryCodesPrintClick.Username,
		}, nil
	case *usageevents.UsageEventOneOf_UiDiscoverStartedEvent:
		ret := &UsageUIDiscoverStartedEvent{
			Metadata: discoverMetadataToPrehog(e.UiDiscoverStartedEvent.Metadata, identityUsername),
			Status:   discoverStatusToPrehog(e.UiDiscoverStartedEvent.Status),
		}
		if err := ret.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}

		return ret, nil
	case *usageevents.UsageEventOneOf_UiDiscoverResourceSelectionEvent:
		ret := &UsageUIDiscoverResourceSelectionEvent{
			Metadata: discoverMetadataToPrehog(e.UiDiscoverResourceSelectionEvent.Metadata, identityUsername),
			Resource: discoverResourceToPrehog(e.UiDiscoverResourceSelectionEvent.Resource),
			Status:   discoverStatusToPrehog(e.UiDiscoverResourceSelectionEvent.Status),
		}
		if err := ret.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}

		return ret, nil
	case *usageevents.UsageEventOneOf_UiDiscoverDeployServiceEvent:
		ret := &UsageUIDiscoverDeployServiceEvent{
			Metadata: discoverMetadataToPrehog(e.UiDiscoverDeployServiceEvent.Metadata, identityUsername),
			Resource: discoverResourceToPrehog(e.UiDiscoverDeployServiceEvent.Resource),
			Status:   discoverStatusToPrehog(e.UiDiscoverDeployServiceEvent.Status),
		}
		if err := ret.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}

		return ret, nil
	case *usageevents.UsageEventOneOf_UiDiscoverDatabaseRegisterEvent:
		ret := &UsageUIDiscoverDatabaseRegisterEvent{
			Metadata: discoverMetadataToPrehog(e.UiDiscoverDatabaseRegisterEvent.Metadata, identityUsername),
			Resource: discoverResourceToPrehog(e.UiDiscoverDatabaseRegisterEvent.Resource),
			Status:   discoverStatusToPrehog(e.UiDiscoverDatabaseRegisterEvent.Status),
		}
		if err := ret.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}

		return ret, nil
	case *usageevents.UsageEventOneOf_UiDiscoverDatabaseConfigureMtlsEvent:
		ret := &UsageUIDiscoverDatabaseConfigureMTLSEvent{
			Metadata: discoverMetadataToPrehog(e.UiDiscoverDatabaseConfigureMtlsEvent.Metadata, identityUsername),
			Resource: discoverResourceToPrehog(e.UiDiscoverDatabaseConfigureMtlsEvent.Resource),
			Status:   discoverStatusToPrehog(e.UiDiscoverDatabaseConfigureMtlsEvent.Status),
		}
		if err := ret.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}

		return ret, nil
	case *usageevents.UsageEventOneOf_UiDiscoverDesktopActiveDirectoryToolsInstallEvent:
		ret := &UsageUIDiscoverDesktopActiveDirectoryToolsInstallEvent{
			Metadata: discoverMetadataToPrehog(e.UiDiscoverDesktopActiveDirectoryToolsInstallEvent.Metadata, identityUsername),
			Resource: discoverResourceToPrehog(e.UiDiscoverDesktopActiveDirectoryToolsInstallEvent.Resource),
			Status:   discoverStatusToPrehog(e.UiDiscoverDesktopActiveDirectoryToolsInstallEvent.Status),
		}
		if err := ret.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}

		return ret, nil
	case *usageevents.UsageEventOneOf_UiDiscoverDesktopActiveDirectoryConfigureEvent:
		ret := &UsageUIDiscoverDesktopActiveDirectoryConfigureEvent{
			Metadata: discoverMetadataToPrehog(e.UiDiscoverDesktopActiveDirectoryConfigureEvent.Metadata, identityUsername),
			Resource: discoverResourceToPrehog(e.UiDiscoverDesktopActiveDirectoryConfigureEvent.Resource),
			Status:   discoverStatusToPrehog(e.UiDiscoverDesktopActiveDirectoryConfigureEvent.Status),
		}
		if err := ret.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}

		return ret, nil
	case *usageevents.UsageEventOneOf_UiDiscoverAutoDiscoveredResourcesEvent:
		ret := &UsageUIDiscoverAutoDiscoveredResourcesEvent{
			Metadata:       discoverMetadataToPrehog(e.UiDiscoverAutoDiscoveredResourcesEvent.Metadata, identityUsername),
			Resource:       discoverResourceToPrehog(e.UiDiscoverAutoDiscoveredResourcesEvent.Resource),
			Status:         discoverStatusToPrehog(e.UiDiscoverAutoDiscoveredResourcesEvent.Status),
			ResourcesCount: e.UiDiscoverAutoDiscoveredResourcesEvent.ResourcesCount,
		}
		if err := ret.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}

		return ret, nil
	case *usageevents.UsageEventOneOf_UiDiscoverDatabaseConfigureIamPolicyEvent:
		ret := &UsageUIDiscoverDatabaseConfigureIAMPolicyEvent{
			Metadata: discoverMetadataToPrehog(e.UiDiscoverDatabaseConfigureIamPolicyEvent.Metadata, identityUsername),
			Resource: discoverResourceToPrehog(e.UiDiscoverDatabaseConfigureIamPolicyEvent.Resource),
			Status:   discoverStatusToPrehog(e.UiDiscoverDatabaseConfigureIamPolicyEvent.Status),
		}
		if err := ret.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}

		return ret, nil
	case *usageevents.UsageEventOneOf_UiDiscoverPrincipalsConfigureEvent:
		ret := &UsageUIDiscoverPrincipalsConfigureEvent{
			Metadata: discoverMetadataToPrehog(e.UiDiscoverPrincipalsConfigureEvent.Metadata, identityUsername),
			Resource: discoverResourceToPrehog(e.UiDiscoverPrincipalsConfigureEvent.Resource),
			Status:   discoverStatusToPrehog(e.UiDiscoverPrincipalsConfigureEvent.Status),
		}
		if err := ret.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}

		return ret, nil
	case *usageevents.UsageEventOneOf_UiDiscoverTestConnectionEvent:
		ret := &UsageUIDiscoverTestConnectionEvent{
			Metadata: discoverMetadataToPrehog(e.UiDiscoverTestConnectionEvent.Metadata, identityUsername),
			Resource: discoverResourceToPrehog(e.UiDiscoverTestConnectionEvent.Resource),
			Status:   discoverStatusToPrehog(e.UiDiscoverTestConnectionEvent.Status),
		}
		if err := ret.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}

		return ret, nil
	case *usageevents.UsageEventOneOf_UiDiscoverCompletedEvent:
		ret := &UsageUIDiscoverCompletedEvent{
			Metadata: discoverMetadataToPrehog(e.UiDiscoverCompletedEvent.Metadata, identityUsername),
			Resource: discoverResourceToPrehog(e.UiDiscoverCompletedEvent.Resource),
			Status:   discoverStatusToPrehog(e.UiDiscoverCompletedEvent.Status),
		}
		if err := ret.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}

		return ret, nil
	default:
		return nil, trace.BadParameter("invalid usage event type %T", event.GetEvent())
	}
}

// TeleportUsageReporter submits Teleport usage events
// anonymized with the cluster name.
type TeleportUsageReporter struct {
	// usageReporter is an actual reporter that batches and sends events
	usageReporter *usagereporter.UsageReporter[prehogv1.SubmitEventRequest]
	// anonymizer is the anonymizer used for filtered audit events.
	anonymizer utils.Anonymizer
	// clusterName is the cluster's name, used for anonymization and as an event
	// field.
	clusterName types.ClusterName
	clock       clockwork.Clock
}

func (t *TeleportUsageReporter) AnonymizeAndSubmit(events ...UsageAnonymizable) error {
	for _, e := range events {
		req := e.Anonymize(t.anonymizer)
		req.Timestamp = timestamppb.New(t.clock.Now())
		req.ClusterName = t.anonymizer.AnonymizeString(t.clusterName.GetClusterName())
		t.usageReporter.AddEventsToQueue(&req)
	}
	return nil
}

func (t *TeleportUsageReporter) Run(ctx context.Context) {
	t.usageReporter.Run(ctx)
}

func NewTeleportUsageReporter(log logrus.FieldLogger, clusterName types.ClusterName, submitter usagereporter.SubmitFunc[prehogv1.SubmitEventRequest]) (*TeleportUsageReporter, error) {
	if log == nil {
		log = logrus.StandardLogger()
	}

	anonymizer, err := utils.NewHMACAnonymizer(clusterName.GetClusterID())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	err = metrics.RegisterPrometheusCollectors(usagereporter.UsagePrometheusCollectors...)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	clock := clockwork.NewRealClock()

	reporter := usagereporter.NewUsageReporter(&usagereporter.Options[prehogv1.SubmitEventRequest]{
		Log:           log,
		Submit:        submitter,
		MinBatchSize:  usageReporterMinBatchSize,
		MaxBatchSize:  usageReporterMaxBatchSize,
		MaxBatchAge:   usageReporterMaxBatchAge,
		MaxBufferSize: usageReporterMaxBufferSize,
		SubmitDelay:   usageReporterSubmitDelay,
		RetryAttempts: usageReporterRetryAttempts,
		Clock:         clock,
	})

	return &TeleportUsageReporter{
		usageReporter: reporter,
		anonymizer:    anonymizer,
		clusterName:   clusterName,
		clock:         clock,
	}, nil
}

func NewPrehogSubmitter(ctx context.Context, prehogEndpoint string, clientCert *tls.Certificate, caCertPEM []byte) (usagereporter.SubmitFunc[prehogv1.SubmitEventRequest], error) {
	tlsConfig := &tls.Config{
		// Self-signed test licenses may not have a proper issuer and won't be
		// used if just passed in via Certificates, so we'll use this to
		// explicitly set the client cert we want to use.
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return clientCert, nil
		},
	}

	if len(caCertPEM) > 0 {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caCertPEM)

		tlsConfig.RootCAs = pool
	}

	httpClient, err := defaults.HTTPClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		return nil, trace.BadParameter("invalid transport type %T", httpClient.Transport)
	}

	transport.Proxy = http.ProxyFromEnvironment
	transport.ForceAttemptHTTP2 = true
	transport.TLSClientConfig = tlsConfig

	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	httpClient.Timeout = 5 * time.Second

	client := prehogclient.NewTeleportReportingServiceClient(httpClient, prehogEndpoint)

	return func(reporter *usagereporter.UsageReporter[prehogv1.SubmitEventRequest], events []*usagereporter.SubmittedEvent[prehogv1.SubmitEventRequest]) ([]*usagereporter.SubmittedEvent[prehogv1.SubmitEventRequest], error) {
		var failed []*usagereporter.SubmittedEvent[prehogv1.SubmitEventRequest]
		var errors []error

		// Note: the backend doesn't support batching at the moment.
		for _, event := range events {
			// Note: this results in retrying the entire batch, which probably
			// isn't ideal.
			req := connect.NewRequest(event.Event)
			if _, err := client.SubmitEvent(ctx, req); err != nil {
				failed = append(failed, event)
				errors = append(errors, err)
			}
		}

		return failed, trace.NewAggregate(errors...)
	}, nil
}

// DiscardUsageReporter is a dummy usage reporter that drops all events.
type DiscardUsageReporter struct{}

func (d *DiscardUsageReporter) AnonymizeAndSubmit(event ...UsageAnonymizable) error {
	// do nothing
	return nil
}

// NewDiscardUsageReporter creates a new usage reporter that drops all events.
func NewDiscardUsageReporter() *DiscardUsageReporter {
	return &DiscardUsageReporter{}
}
