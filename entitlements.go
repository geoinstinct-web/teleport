package teleport

// EntitlementKind should be 1:1 with the Features & FeatureStrings in salescenter/product/product.go
// Drops CustomTheme from master list
type EntitlementKind string

const (
	AccessLists            EntitlementKind = "AccessLists"
	AccessMonitoring       EntitlementKind = "AccessMonitoring"
	AccessRequests         EntitlementKind = "AccessRequests"
	App                    EntitlementKind = "App"
	Assist                 EntitlementKind = "Assist"
	CloudAuditLogRetention EntitlementKind = "CloudAuditLogRetention"
	DB                     EntitlementKind = "DB"
	Desktop                EntitlementKind = "Desktop"
	DeviceTrust            EntitlementKind = "DeviceTrust"
	ExternalAuditStorage   EntitlementKind = "ExternalAuditStorage"
	FeatureHiding          EntitlementKind = "FeatureHiding"
	HSM                    EntitlementKind = "HSM"
	Identity               EntitlementKind = "Identity"
	JoinActiveSessions     EntitlementKind = "JoinActiveSessions"
	K8s                    EntitlementKind = "K8s"
	MobileDeviceManagement EntitlementKind = "MobileDeviceManagement"
	OIDC                   EntitlementKind = "OIDC"
	OktaSCIM               EntitlementKind = "OktaSCIM"
	OktaUserSync           EntitlementKind = "OktaUserSync"
	Policy                 EntitlementKind = "Policy"
	SAML                   EntitlementKind = "SAML"
	SessionLocks           EntitlementKind = "SessionLocks"
	UpsellAlert            EntitlementKind = "UpsellAlert"
	UsageReporting         EntitlementKind = "UsageReporting"
)
