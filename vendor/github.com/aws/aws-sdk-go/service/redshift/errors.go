// Code generated by private/model/cli/gen-api/main.go. DO NOT EDIT.

package redshift

const (

	// ErrCodeAccessToClusterDeniedFault for service response error code
	// "AccessToClusterDenied".
	//
	// You are not authorized to access the cluster.
	ErrCodeAccessToClusterDeniedFault = "AccessToClusterDenied"

	// ErrCodeAccessToSnapshotDeniedFault for service response error code
	// "AccessToSnapshotDenied".
	//
	// The owner of the specified snapshot has not authorized your account to access
	// the snapshot.
	ErrCodeAccessToSnapshotDeniedFault = "AccessToSnapshotDenied"

	// ErrCodeAuthenticationProfileAlreadyExistsFault for service response error code
	// "AuthenticationProfileAlreadyExistsFault".
	//
	// The authentication profile already exists.
	ErrCodeAuthenticationProfileAlreadyExistsFault = "AuthenticationProfileAlreadyExistsFault"

	// ErrCodeAuthenticationProfileNotFoundFault for service response error code
	// "AuthenticationProfileNotFoundFault".
	//
	// The authentication profile can't be found.
	ErrCodeAuthenticationProfileNotFoundFault = "AuthenticationProfileNotFoundFault"

	// ErrCodeAuthenticationProfileQuotaExceededFault for service response error code
	// "AuthenticationProfileQuotaExceededFault".
	//
	// The size or number of authentication profiles has exceeded the quota. The
	// maximum length of the JSON string and maximum number of authentication profiles
	// is determined by a quota for your account.
	ErrCodeAuthenticationProfileQuotaExceededFault = "AuthenticationProfileQuotaExceededFault"

	// ErrCodeAuthorizationAlreadyExistsFault for service response error code
	// "AuthorizationAlreadyExists".
	//
	// The specified CIDR block or EC2 security group is already authorized for
	// the specified cluster security group.
	ErrCodeAuthorizationAlreadyExistsFault = "AuthorizationAlreadyExists"

	// ErrCodeAuthorizationNotFoundFault for service response error code
	// "AuthorizationNotFound".
	//
	// The specified CIDR IP range or EC2 security group is not authorized for the
	// specified cluster security group.
	ErrCodeAuthorizationNotFoundFault = "AuthorizationNotFound"

	// ErrCodeAuthorizationQuotaExceededFault for service response error code
	// "AuthorizationQuotaExceeded".
	//
	// The authorization quota for the cluster security group has been reached.
	ErrCodeAuthorizationQuotaExceededFault = "AuthorizationQuotaExceeded"

	// ErrCodeBatchDeleteRequestSizeExceededFault for service response error code
	// "BatchDeleteRequestSizeExceeded".
	//
	// The maximum number for a batch delete of snapshots has been reached. The
	// limit is 100.
	ErrCodeBatchDeleteRequestSizeExceededFault = "BatchDeleteRequestSizeExceeded"

	// ErrCodeBatchModifyClusterSnapshotsLimitExceededFault for service response error code
	// "BatchModifyClusterSnapshotsLimitExceededFault".
	//
	// The maximum number for snapshot identifiers has been reached. The limit is
	// 100.
	ErrCodeBatchModifyClusterSnapshotsLimitExceededFault = "BatchModifyClusterSnapshotsLimitExceededFault"

	// ErrCodeBucketNotFoundFault for service response error code
	// "BucketNotFoundFault".
	//
	// Could not find the specified S3 bucket.
	ErrCodeBucketNotFoundFault = "BucketNotFoundFault"

	// ErrCodeClusterAlreadyExistsFault for service response error code
	// "ClusterAlreadyExists".
	//
	// The account already has a cluster with the given identifier.
	ErrCodeClusterAlreadyExistsFault = "ClusterAlreadyExists"

	// ErrCodeClusterNotFoundFault for service response error code
	// "ClusterNotFound".
	//
	// The ClusterIdentifier parameter does not refer to an existing cluster.
	ErrCodeClusterNotFoundFault = "ClusterNotFound"

	// ErrCodeClusterOnLatestRevisionFault for service response error code
	// "ClusterOnLatestRevision".
	//
	// Cluster is already on the latest database revision.
	ErrCodeClusterOnLatestRevisionFault = "ClusterOnLatestRevision"

	// ErrCodeClusterParameterGroupAlreadyExistsFault for service response error code
	// "ClusterParameterGroupAlreadyExists".
	//
	// A cluster parameter group with the same name already exists.
	ErrCodeClusterParameterGroupAlreadyExistsFault = "ClusterParameterGroupAlreadyExists"

	// ErrCodeClusterParameterGroupNotFoundFault for service response error code
	// "ClusterParameterGroupNotFound".
	//
	// The parameter group name does not refer to an existing parameter group.
	ErrCodeClusterParameterGroupNotFoundFault = "ClusterParameterGroupNotFound"

	// ErrCodeClusterParameterGroupQuotaExceededFault for service response error code
	// "ClusterParameterGroupQuotaExceeded".
	//
	// The request would result in the user exceeding the allowed number of cluster
	// parameter groups. For information about increasing your quota, go to Limits
	// in Amazon Redshift (https://docs.aws.amazon.com/redshift/latest/mgmt/amazon-redshift-limits.html)
	// in the Amazon Redshift Cluster Management Guide.
	ErrCodeClusterParameterGroupQuotaExceededFault = "ClusterParameterGroupQuotaExceeded"

	// ErrCodeClusterQuotaExceededFault for service response error code
	// "ClusterQuotaExceeded".
	//
	// The request would exceed the allowed number of cluster instances for this
	// account. For information about increasing your quota, go to Limits in Amazon
	// Redshift (https://docs.aws.amazon.com/redshift/latest/mgmt/amazon-redshift-limits.html)
	// in the Amazon Redshift Cluster Management Guide.
	ErrCodeClusterQuotaExceededFault = "ClusterQuotaExceeded"

	// ErrCodeClusterSecurityGroupAlreadyExistsFault for service response error code
	// "ClusterSecurityGroupAlreadyExists".
	//
	// A cluster security group with the same name already exists.
	ErrCodeClusterSecurityGroupAlreadyExistsFault = "ClusterSecurityGroupAlreadyExists"

	// ErrCodeClusterSecurityGroupNotFoundFault for service response error code
	// "ClusterSecurityGroupNotFound".
	//
	// The cluster security group name does not refer to an existing cluster security
	// group.
	ErrCodeClusterSecurityGroupNotFoundFault = "ClusterSecurityGroupNotFound"

	// ErrCodeClusterSecurityGroupQuotaExceededFault for service response error code
	// "QuotaExceeded.ClusterSecurityGroup".
	//
	// The request would result in the user exceeding the allowed number of cluster
	// security groups. For information about increasing your quota, go to Limits
	// in Amazon Redshift (https://docs.aws.amazon.com/redshift/latest/mgmt/amazon-redshift-limits.html)
	// in the Amazon Redshift Cluster Management Guide.
	ErrCodeClusterSecurityGroupQuotaExceededFault = "QuotaExceeded.ClusterSecurityGroup"

	// ErrCodeClusterSnapshotAlreadyExistsFault for service response error code
	// "ClusterSnapshotAlreadyExists".
	//
	// The value specified as a snapshot identifier is already used by an existing
	// snapshot.
	ErrCodeClusterSnapshotAlreadyExistsFault = "ClusterSnapshotAlreadyExists"

	// ErrCodeClusterSnapshotNotFoundFault for service response error code
	// "ClusterSnapshotNotFound".
	//
	// The snapshot identifier does not refer to an existing cluster snapshot.
	ErrCodeClusterSnapshotNotFoundFault = "ClusterSnapshotNotFound"

	// ErrCodeClusterSnapshotQuotaExceededFault for service response error code
	// "ClusterSnapshotQuotaExceeded".
	//
	// The request would result in the user exceeding the allowed number of cluster
	// snapshots.
	ErrCodeClusterSnapshotQuotaExceededFault = "ClusterSnapshotQuotaExceeded"

	// ErrCodeClusterSubnetGroupAlreadyExistsFault for service response error code
	// "ClusterSubnetGroupAlreadyExists".
	//
	// A ClusterSubnetGroupName is already used by an existing cluster subnet group.
	ErrCodeClusterSubnetGroupAlreadyExistsFault = "ClusterSubnetGroupAlreadyExists"

	// ErrCodeClusterSubnetGroupNotFoundFault for service response error code
	// "ClusterSubnetGroupNotFoundFault".
	//
	// The cluster subnet group name does not refer to an existing cluster subnet
	// group.
	ErrCodeClusterSubnetGroupNotFoundFault = "ClusterSubnetGroupNotFoundFault"

	// ErrCodeClusterSubnetGroupQuotaExceededFault for service response error code
	// "ClusterSubnetGroupQuotaExceeded".
	//
	// The request would result in user exceeding the allowed number of cluster
	// subnet groups. For information about increasing your quota, go to Limits
	// in Amazon Redshift (https://docs.aws.amazon.com/redshift/latest/mgmt/amazon-redshift-limits.html)
	// in the Amazon Redshift Cluster Management Guide.
	ErrCodeClusterSubnetGroupQuotaExceededFault = "ClusterSubnetGroupQuotaExceeded"

	// ErrCodeClusterSubnetQuotaExceededFault for service response error code
	// "ClusterSubnetQuotaExceededFault".
	//
	// The request would result in user exceeding the allowed number of subnets
	// in a cluster subnet groups. For information about increasing your quota,
	// go to Limits in Amazon Redshift (https://docs.aws.amazon.com/redshift/latest/mgmt/amazon-redshift-limits.html)
	// in the Amazon Redshift Cluster Management Guide.
	ErrCodeClusterSubnetQuotaExceededFault = "ClusterSubnetQuotaExceededFault"

	// ErrCodeCopyToRegionDisabledFault for service response error code
	// "CopyToRegionDisabledFault".
	//
	// Cross-region snapshot copy was temporarily disabled. Try your request again.
	ErrCodeCopyToRegionDisabledFault = "CopyToRegionDisabledFault"

	// ErrCodeDependentServiceRequestThrottlingFault for service response error code
	// "DependentServiceRequestThrottlingFault".
	//
	// The request cannot be completed because a dependent service is throttling
	// requests made by Amazon Redshift on your behalf. Wait and retry the request.
	ErrCodeDependentServiceRequestThrottlingFault = "DependentServiceRequestThrottlingFault"

	// ErrCodeDependentServiceUnavailableFault for service response error code
	// "DependentServiceUnavailableFault".
	//
	// Your request cannot be completed because a dependent internal service is
	// temporarily unavailable. Wait 30 to 60 seconds and try again.
	ErrCodeDependentServiceUnavailableFault = "DependentServiceUnavailableFault"

	// ErrCodeEndpointAlreadyExistsFault for service response error code
	// "EndpointAlreadyExists".
	//
	// The account already has a Redshift-managed VPC endpoint with the given identifier.
	ErrCodeEndpointAlreadyExistsFault = "EndpointAlreadyExists"

	// ErrCodeEndpointAuthorizationAlreadyExistsFault for service response error code
	// "EndpointAuthorizationAlreadyExists".
	//
	// The authorization already exists for this endpoint.
	ErrCodeEndpointAuthorizationAlreadyExistsFault = "EndpointAuthorizationAlreadyExists"

	// ErrCodeEndpointAuthorizationNotFoundFault for service response error code
	// "EndpointAuthorizationNotFound".
	//
	// The authorization for this endpoint can't be found.
	ErrCodeEndpointAuthorizationNotFoundFault = "EndpointAuthorizationNotFound"

	// ErrCodeEndpointAuthorizationsPerClusterLimitExceededFault for service response error code
	// "EndpointAuthorizationsPerClusterLimitExceeded".
	//
	// The number of endpoint authorizations per cluster has exceeded its limit.
	ErrCodeEndpointAuthorizationsPerClusterLimitExceededFault = "EndpointAuthorizationsPerClusterLimitExceeded"

	// ErrCodeEndpointNotFoundFault for service response error code
	// "EndpointNotFound".
	//
	// The endpoint name doesn't refer to an existing endpoint.
	ErrCodeEndpointNotFoundFault = "EndpointNotFound"

	// ErrCodeEndpointsPerAuthorizationLimitExceededFault for service response error code
	// "EndpointsPerAuthorizationLimitExceeded".
	//
	// The number of Redshift-managed VPC endpoints per authorization has exceeded
	// its limit.
	ErrCodeEndpointsPerAuthorizationLimitExceededFault = "EndpointsPerAuthorizationLimitExceeded"

	// ErrCodeEndpointsPerClusterLimitExceededFault for service response error code
	// "EndpointsPerClusterLimitExceeded".
	//
	// The number of Redshift-managed VPC endpoints per cluster has exceeded its
	// limit.
	ErrCodeEndpointsPerClusterLimitExceededFault = "EndpointsPerClusterLimitExceeded"

	// ErrCodeEventSubscriptionQuotaExceededFault for service response error code
	// "EventSubscriptionQuotaExceeded".
	//
	// The request would exceed the allowed number of event subscriptions for this
	// account. For information about increasing your quota, go to Limits in Amazon
	// Redshift (https://docs.aws.amazon.com/redshift/latest/mgmt/amazon-redshift-limits.html)
	// in the Amazon Redshift Cluster Management Guide.
	ErrCodeEventSubscriptionQuotaExceededFault = "EventSubscriptionQuotaExceeded"

	// ErrCodeHsmClientCertificateAlreadyExistsFault for service response error code
	// "HsmClientCertificateAlreadyExistsFault".
	//
	// There is already an existing Amazon Redshift HSM client certificate with
	// the specified identifier.
	ErrCodeHsmClientCertificateAlreadyExistsFault = "HsmClientCertificateAlreadyExistsFault"

	// ErrCodeHsmClientCertificateNotFoundFault for service response error code
	// "HsmClientCertificateNotFoundFault".
	//
	// There is no Amazon Redshift HSM client certificate with the specified identifier.
	ErrCodeHsmClientCertificateNotFoundFault = "HsmClientCertificateNotFoundFault"

	// ErrCodeHsmClientCertificateQuotaExceededFault for service response error code
	// "HsmClientCertificateQuotaExceededFault".
	//
	// The quota for HSM client certificates has been reached. For information about
	// increasing your quota, go to Limits in Amazon Redshift (https://docs.aws.amazon.com/redshift/latest/mgmt/amazon-redshift-limits.html)
	// in the Amazon Redshift Cluster Management Guide.
	ErrCodeHsmClientCertificateQuotaExceededFault = "HsmClientCertificateQuotaExceededFault"

	// ErrCodeHsmConfigurationAlreadyExistsFault for service response error code
	// "HsmConfigurationAlreadyExistsFault".
	//
	// There is already an existing Amazon Redshift HSM configuration with the specified
	// identifier.
	ErrCodeHsmConfigurationAlreadyExistsFault = "HsmConfigurationAlreadyExistsFault"

	// ErrCodeHsmConfigurationNotFoundFault for service response error code
	// "HsmConfigurationNotFoundFault".
	//
	// There is no Amazon Redshift HSM configuration with the specified identifier.
	ErrCodeHsmConfigurationNotFoundFault = "HsmConfigurationNotFoundFault"

	// ErrCodeHsmConfigurationQuotaExceededFault for service response error code
	// "HsmConfigurationQuotaExceededFault".
	//
	// The quota for HSM configurations has been reached. For information about
	// increasing your quota, go to Limits in Amazon Redshift (https://docs.aws.amazon.com/redshift/latest/mgmt/amazon-redshift-limits.html)
	// in the Amazon Redshift Cluster Management Guide.
	ErrCodeHsmConfigurationQuotaExceededFault = "HsmConfigurationQuotaExceededFault"

	// ErrCodeInProgressTableRestoreQuotaExceededFault for service response error code
	// "InProgressTableRestoreQuotaExceededFault".
	//
	// You have exceeded the allowed number of table restore requests. Wait for
	// your current table restore requests to complete before making a new request.
	ErrCodeInProgressTableRestoreQuotaExceededFault = "InProgressTableRestoreQuotaExceededFault"

	// ErrCodeIncompatibleOrderableOptions for service response error code
	// "IncompatibleOrderableOptions".
	//
	// The specified options are incompatible.
	ErrCodeIncompatibleOrderableOptions = "IncompatibleOrderableOptions"

	// ErrCodeInsufficientClusterCapacityFault for service response error code
	// "InsufficientClusterCapacity".
	//
	// The number of nodes specified exceeds the allotted capacity of the cluster.
	ErrCodeInsufficientClusterCapacityFault = "InsufficientClusterCapacity"

	// ErrCodeInsufficientS3BucketPolicyFault for service response error code
	// "InsufficientS3BucketPolicyFault".
	//
	// The cluster does not have read bucket or put object permissions on the S3
	// bucket specified when enabling logging.
	ErrCodeInsufficientS3BucketPolicyFault = "InsufficientS3BucketPolicyFault"

	// ErrCodeInvalidAuthenticationProfileRequestFault for service response error code
	// "InvalidAuthenticationProfileRequestFault".
	//
	// The authentication profile request is not valid. The profile name can't be
	// null or empty. The authentication profile API operation must be available
	// in the Amazon Web Services Region.
	ErrCodeInvalidAuthenticationProfileRequestFault = "InvalidAuthenticationProfileRequestFault"

	// ErrCodeInvalidAuthorizationStateFault for service response error code
	// "InvalidAuthorizationState".
	//
	// The status of the authorization is not valid.
	ErrCodeInvalidAuthorizationStateFault = "InvalidAuthorizationState"

	// ErrCodeInvalidClusterParameterGroupStateFault for service response error code
	// "InvalidClusterParameterGroupState".
	//
	// The cluster parameter group action can not be completed because another task
	// is in progress that involves the parameter group. Wait a few moments and
	// try the operation again.
	ErrCodeInvalidClusterParameterGroupStateFault = "InvalidClusterParameterGroupState"

	// ErrCodeInvalidClusterSecurityGroupStateFault for service response error code
	// "InvalidClusterSecurityGroupState".
	//
	// The state of the cluster security group is not available.
	ErrCodeInvalidClusterSecurityGroupStateFault = "InvalidClusterSecurityGroupState"

	// ErrCodeInvalidClusterSnapshotScheduleStateFault for service response error code
	// "InvalidClusterSnapshotScheduleState".
	//
	// The cluster snapshot schedule state is not valid.
	ErrCodeInvalidClusterSnapshotScheduleStateFault = "InvalidClusterSnapshotScheduleState"

	// ErrCodeInvalidClusterSnapshotStateFault for service response error code
	// "InvalidClusterSnapshotState".
	//
	// The specified cluster snapshot is not in the available state, or other accounts
	// are authorized to access the snapshot.
	ErrCodeInvalidClusterSnapshotStateFault = "InvalidClusterSnapshotState"

	// ErrCodeInvalidClusterStateFault for service response error code
	// "InvalidClusterState".
	//
	// The specified cluster is not in the available state.
	ErrCodeInvalidClusterStateFault = "InvalidClusterState"

	// ErrCodeInvalidClusterSubnetGroupStateFault for service response error code
	// "InvalidClusterSubnetGroupStateFault".
	//
	// The cluster subnet group cannot be deleted because it is in use.
	ErrCodeInvalidClusterSubnetGroupStateFault = "InvalidClusterSubnetGroupStateFault"

	// ErrCodeInvalidClusterSubnetStateFault for service response error code
	// "InvalidClusterSubnetStateFault".
	//
	// The state of the subnet is invalid.
	ErrCodeInvalidClusterSubnetStateFault = "InvalidClusterSubnetStateFault"

	// ErrCodeInvalidClusterTrackFault for service response error code
	// "InvalidClusterTrack".
	//
	// The provided cluster track name is not valid.
	ErrCodeInvalidClusterTrackFault = "InvalidClusterTrack"

	// ErrCodeInvalidDataShareFault for service response error code
	// "InvalidDataShareFault".
	//
	// There is an error with the datashare.
	ErrCodeInvalidDataShareFault = "InvalidDataShareFault"

	// ErrCodeInvalidElasticIpFault for service response error code
	// "InvalidElasticIpFault".
	//
	// The Elastic IP (EIP) is invalid or cannot be found.
	ErrCodeInvalidElasticIpFault = "InvalidElasticIpFault"

	// ErrCodeInvalidEndpointStateFault for service response error code
	// "InvalidEndpointState".
	//
	// The status of the endpoint is not valid.
	ErrCodeInvalidEndpointStateFault = "InvalidEndpointState"

	// ErrCodeInvalidHsmClientCertificateStateFault for service response error code
	// "InvalidHsmClientCertificateStateFault".
	//
	// The specified HSM client certificate is not in the available state, or it
	// is still in use by one or more Amazon Redshift clusters.
	ErrCodeInvalidHsmClientCertificateStateFault = "InvalidHsmClientCertificateStateFault"

	// ErrCodeInvalidHsmConfigurationStateFault for service response error code
	// "InvalidHsmConfigurationStateFault".
	//
	// The specified HSM configuration is not in the available state, or it is still
	// in use by one or more Amazon Redshift clusters.
	ErrCodeInvalidHsmConfigurationStateFault = "InvalidHsmConfigurationStateFault"

	// ErrCodeInvalidNamespaceFault for service response error code
	// "InvalidNamespaceFault".
	//
	// The namespace isn't valid because the namespace doesn't exist. Provide a
	// valid namespace.
	ErrCodeInvalidNamespaceFault = "InvalidNamespaceFault"

	// ErrCodeInvalidReservedNodeStateFault for service response error code
	// "InvalidReservedNodeState".
	//
	// Indicates that the Reserved Node being exchanged is not in an active state.
	ErrCodeInvalidReservedNodeStateFault = "InvalidReservedNodeState"

	// ErrCodeInvalidRestoreFault for service response error code
	// "InvalidRestore".
	//
	// The restore is invalid.
	ErrCodeInvalidRestoreFault = "InvalidRestore"

	// ErrCodeInvalidRetentionPeriodFault for service response error code
	// "InvalidRetentionPeriodFault".
	//
	// The retention period specified is either in the past or is not a valid value.
	//
	// The value must be either -1 or an integer between 1 and 3,653.
	ErrCodeInvalidRetentionPeriodFault = "InvalidRetentionPeriodFault"

	// ErrCodeInvalidS3BucketNameFault for service response error code
	// "InvalidS3BucketNameFault".
	//
	// The S3 bucket name is invalid. For more information about naming rules, go
	// to Bucket Restrictions and Limitations (https://docs.aws.amazon.com/AmazonS3/latest/dev/BucketRestrictions.html)
	// in the Amazon Simple Storage Service (S3) Developer Guide.
	ErrCodeInvalidS3BucketNameFault = "InvalidS3BucketNameFault"

	// ErrCodeInvalidS3KeyPrefixFault for service response error code
	// "InvalidS3KeyPrefixFault".
	//
	// The string specified for the logging S3 key prefix does not comply with the
	// documented constraints.
	ErrCodeInvalidS3KeyPrefixFault = "InvalidS3KeyPrefixFault"

	// ErrCodeInvalidScheduleFault for service response error code
	// "InvalidSchedule".
	//
	// The schedule you submitted isn't valid.
	ErrCodeInvalidScheduleFault = "InvalidSchedule"

	// ErrCodeInvalidScheduledActionFault for service response error code
	// "InvalidScheduledAction".
	//
	// The scheduled action is not valid.
	ErrCodeInvalidScheduledActionFault = "InvalidScheduledAction"

	// ErrCodeInvalidSnapshotCopyGrantStateFault for service response error code
	// "InvalidSnapshotCopyGrantStateFault".
	//
	// The snapshot copy grant can't be deleted because it is used by one or more
	// clusters.
	ErrCodeInvalidSnapshotCopyGrantStateFault = "InvalidSnapshotCopyGrantStateFault"

	// ErrCodeInvalidSubnet for service response error code
	// "InvalidSubnet".
	//
	// The requested subnet is not valid, or not all of the subnets are in the same
	// VPC.
	ErrCodeInvalidSubnet = "InvalidSubnet"

	// ErrCodeInvalidSubscriptionStateFault for service response error code
	// "InvalidSubscriptionStateFault".
	//
	// The subscription request is invalid because it is a duplicate request. This
	// subscription request is already in progress.
	ErrCodeInvalidSubscriptionStateFault = "InvalidSubscriptionStateFault"

	// ErrCodeInvalidTableRestoreArgumentFault for service response error code
	// "InvalidTableRestoreArgument".
	//
	// The value specified for the sourceDatabaseName, sourceSchemaName, or sourceTableName
	// parameter, or a combination of these, doesn't exist in the snapshot.
	ErrCodeInvalidTableRestoreArgumentFault = "InvalidTableRestoreArgument"

	// ErrCodeInvalidTagFault for service response error code
	// "InvalidTagFault".
	//
	// The tag is invalid.
	ErrCodeInvalidTagFault = "InvalidTagFault"

	// ErrCodeInvalidUsageLimitFault for service response error code
	// "InvalidUsageLimit".
	//
	// The usage limit is not valid.
	ErrCodeInvalidUsageLimitFault = "InvalidUsageLimit"

	// ErrCodeInvalidVPCNetworkStateFault for service response error code
	// "InvalidVPCNetworkStateFault".
	//
	// The cluster subnet group does not cover all Availability Zones.
	ErrCodeInvalidVPCNetworkStateFault = "InvalidVPCNetworkStateFault"

	// ErrCodeLimitExceededFault for service response error code
	// "LimitExceededFault".
	//
	// The encryption key has exceeded its grant limit in Amazon Web Services KMS.
	ErrCodeLimitExceededFault = "LimitExceededFault"

	// ErrCodeNumberOfNodesPerClusterLimitExceededFault for service response error code
	// "NumberOfNodesPerClusterLimitExceeded".
	//
	// The operation would exceed the number of nodes allowed for a cluster.
	ErrCodeNumberOfNodesPerClusterLimitExceededFault = "NumberOfNodesPerClusterLimitExceeded"

	// ErrCodeNumberOfNodesQuotaExceededFault for service response error code
	// "NumberOfNodesQuotaExceeded".
	//
	// The operation would exceed the number of nodes allotted to the account. For
	// information about increasing your quota, go to Limits in Amazon Redshift
	// (https://docs.aws.amazon.com/redshift/latest/mgmt/amazon-redshift-limits.html)
	// in the Amazon Redshift Cluster Management Guide.
	ErrCodeNumberOfNodesQuotaExceededFault = "NumberOfNodesQuotaExceeded"

	// ErrCodePartnerNotFoundFault for service response error code
	// "PartnerNotFound".
	//
	// The name of the partner was not found.
	ErrCodePartnerNotFoundFault = "PartnerNotFound"

	// ErrCodeReservedNodeAlreadyExistsFault for service response error code
	// "ReservedNodeAlreadyExists".
	//
	// User already has a reservation with the given identifier.
	ErrCodeReservedNodeAlreadyExistsFault = "ReservedNodeAlreadyExists"

	// ErrCodeReservedNodeAlreadyMigratedFault for service response error code
	// "ReservedNodeAlreadyMigrated".
	//
	// Indicates that the reserved node has already been exchanged.
	ErrCodeReservedNodeAlreadyMigratedFault = "ReservedNodeAlreadyMigrated"

	// ErrCodeReservedNodeExchangeNotFoundFault for service response error code
	// "ReservedNodeExchangeNotFond".
	//
	// The reserved-node exchange status wasn't found.
	ErrCodeReservedNodeExchangeNotFoundFault = "ReservedNodeExchangeNotFond"

	// ErrCodeReservedNodeNotFoundFault for service response error code
	// "ReservedNodeNotFound".
	//
	// The specified reserved compute node not found.
	ErrCodeReservedNodeNotFoundFault = "ReservedNodeNotFound"

	// ErrCodeReservedNodeOfferingNotFoundFault for service response error code
	// "ReservedNodeOfferingNotFound".
	//
	// Specified offering does not exist.
	ErrCodeReservedNodeOfferingNotFoundFault = "ReservedNodeOfferingNotFound"

	// ErrCodeReservedNodeQuotaExceededFault for service response error code
	// "ReservedNodeQuotaExceeded".
	//
	// Request would exceed the user's compute node quota. For information about
	// increasing your quota, go to Limits in Amazon Redshift (https://docs.aws.amazon.com/redshift/latest/mgmt/amazon-redshift-limits.html)
	// in the Amazon Redshift Cluster Management Guide.
	ErrCodeReservedNodeQuotaExceededFault = "ReservedNodeQuotaExceeded"

	// ErrCodeResizeNotFoundFault for service response error code
	// "ResizeNotFound".
	//
	// A resize operation for the specified cluster is not found.
	ErrCodeResizeNotFoundFault = "ResizeNotFound"

	// ErrCodeResourceNotFoundFault for service response error code
	// "ResourceNotFoundFault".
	//
	// The resource could not be found.
	ErrCodeResourceNotFoundFault = "ResourceNotFoundFault"

	// ErrCodeSNSInvalidTopicFault for service response error code
	// "SNSInvalidTopic".
	//
	// Amazon SNS has responded that there is a problem with the specified Amazon
	// SNS topic.
	ErrCodeSNSInvalidTopicFault = "SNSInvalidTopic"

	// ErrCodeSNSNoAuthorizationFault for service response error code
	// "SNSNoAuthorization".
	//
	// You do not have permission to publish to the specified Amazon SNS topic.
	ErrCodeSNSNoAuthorizationFault = "SNSNoAuthorization"

	// ErrCodeSNSTopicArnNotFoundFault for service response error code
	// "SNSTopicArnNotFound".
	//
	// An Amazon SNS topic with the specified Amazon Resource Name (ARN) does not
	// exist.
	ErrCodeSNSTopicArnNotFoundFault = "SNSTopicArnNotFound"

	// ErrCodeScheduleDefinitionTypeUnsupportedFault for service response error code
	// "ScheduleDefinitionTypeUnsupported".
	//
	// The definition you submitted is not supported.
	ErrCodeScheduleDefinitionTypeUnsupportedFault = "ScheduleDefinitionTypeUnsupported"

	// ErrCodeScheduledActionAlreadyExistsFault for service response error code
	// "ScheduledActionAlreadyExists".
	//
	// The scheduled action already exists.
	ErrCodeScheduledActionAlreadyExistsFault = "ScheduledActionAlreadyExists"

	// ErrCodeScheduledActionNotFoundFault for service response error code
	// "ScheduledActionNotFound".
	//
	// The scheduled action cannot be found.
	ErrCodeScheduledActionNotFoundFault = "ScheduledActionNotFound"

	// ErrCodeScheduledActionQuotaExceededFault for service response error code
	// "ScheduledActionQuotaExceeded".
	//
	// The quota for scheduled actions exceeded.
	ErrCodeScheduledActionQuotaExceededFault = "ScheduledActionQuotaExceeded"

	// ErrCodeScheduledActionTypeUnsupportedFault for service response error code
	// "ScheduledActionTypeUnsupported".
	//
	// The action type specified for a scheduled action is not supported.
	ErrCodeScheduledActionTypeUnsupportedFault = "ScheduledActionTypeUnsupported"

	// ErrCodeSnapshotCopyAlreadyDisabledFault for service response error code
	// "SnapshotCopyAlreadyDisabledFault".
	//
	// The cluster already has cross-region snapshot copy disabled.
	ErrCodeSnapshotCopyAlreadyDisabledFault = "SnapshotCopyAlreadyDisabledFault"

	// ErrCodeSnapshotCopyAlreadyEnabledFault for service response error code
	// "SnapshotCopyAlreadyEnabledFault".
	//
	// The cluster already has cross-region snapshot copy enabled.
	ErrCodeSnapshotCopyAlreadyEnabledFault = "SnapshotCopyAlreadyEnabledFault"

	// ErrCodeSnapshotCopyDisabledFault for service response error code
	// "SnapshotCopyDisabledFault".
	//
	// Cross-region snapshot copy was temporarily disabled. Try your request again.
	ErrCodeSnapshotCopyDisabledFault = "SnapshotCopyDisabledFault"

	// ErrCodeSnapshotCopyGrantAlreadyExistsFault for service response error code
	// "SnapshotCopyGrantAlreadyExistsFault".
	//
	// The snapshot copy grant can't be created because a grant with the same name
	// already exists.
	ErrCodeSnapshotCopyGrantAlreadyExistsFault = "SnapshotCopyGrantAlreadyExistsFault"

	// ErrCodeSnapshotCopyGrantNotFoundFault for service response error code
	// "SnapshotCopyGrantNotFoundFault".
	//
	// The specified snapshot copy grant can't be found. Make sure that the name
	// is typed correctly and that the grant exists in the destination region.
	ErrCodeSnapshotCopyGrantNotFoundFault = "SnapshotCopyGrantNotFoundFault"

	// ErrCodeSnapshotCopyGrantQuotaExceededFault for service response error code
	// "SnapshotCopyGrantQuotaExceededFault".
	//
	// The Amazon Web Services account has exceeded the maximum number of snapshot
	// copy grants in this region.
	ErrCodeSnapshotCopyGrantQuotaExceededFault = "SnapshotCopyGrantQuotaExceededFault"

	// ErrCodeSnapshotScheduleAlreadyExistsFault for service response error code
	// "SnapshotScheduleAlreadyExists".
	//
	// The specified snapshot schedule already exists.
	ErrCodeSnapshotScheduleAlreadyExistsFault = "SnapshotScheduleAlreadyExists"

	// ErrCodeSnapshotScheduleNotFoundFault for service response error code
	// "SnapshotScheduleNotFound".
	//
	// We could not find the specified snapshot schedule.
	ErrCodeSnapshotScheduleNotFoundFault = "SnapshotScheduleNotFound"

	// ErrCodeSnapshotScheduleQuotaExceededFault for service response error code
	// "SnapshotScheduleQuotaExceeded".
	//
	// You have exceeded the quota of snapshot schedules.
	ErrCodeSnapshotScheduleQuotaExceededFault = "SnapshotScheduleQuotaExceeded"

	// ErrCodeSnapshotScheduleUpdateInProgressFault for service response error code
	// "SnapshotScheduleUpdateInProgress".
	//
	// The specified snapshot schedule is already being updated.
	ErrCodeSnapshotScheduleUpdateInProgressFault = "SnapshotScheduleUpdateInProgress"

	// ErrCodeSourceNotFoundFault for service response error code
	// "SourceNotFound".
	//
	// The specified Amazon Redshift event source could not be found.
	ErrCodeSourceNotFoundFault = "SourceNotFound"

	// ErrCodeSubnetAlreadyInUse for service response error code
	// "SubnetAlreadyInUse".
	//
	// A specified subnet is already in use by another cluster.
	ErrCodeSubnetAlreadyInUse = "SubnetAlreadyInUse"

	// ErrCodeSubscriptionAlreadyExistFault for service response error code
	// "SubscriptionAlreadyExist".
	//
	// There is already an existing event notification subscription with the specified
	// name.
	ErrCodeSubscriptionAlreadyExistFault = "SubscriptionAlreadyExist"

	// ErrCodeSubscriptionCategoryNotFoundFault for service response error code
	// "SubscriptionCategoryNotFound".
	//
	// The value specified for the event category was not one of the allowed values,
	// or it specified a category that does not apply to the specified source type.
	// The allowed values are Configuration, Management, Monitoring, and Security.
	ErrCodeSubscriptionCategoryNotFoundFault = "SubscriptionCategoryNotFound"

	// ErrCodeSubscriptionEventIdNotFoundFault for service response error code
	// "SubscriptionEventIdNotFound".
	//
	// An Amazon Redshift event with the specified event ID does not exist.
	ErrCodeSubscriptionEventIdNotFoundFault = "SubscriptionEventIdNotFound"

	// ErrCodeSubscriptionNotFoundFault for service response error code
	// "SubscriptionNotFound".
	//
	// An Amazon Redshift event notification subscription with the specified name
	// does not exist.
	ErrCodeSubscriptionNotFoundFault = "SubscriptionNotFound"

	// ErrCodeSubscriptionSeverityNotFoundFault for service response error code
	// "SubscriptionSeverityNotFound".
	//
	// The value specified for the event severity was not one of the allowed values,
	// or it specified a severity that does not apply to the specified source type.
	// The allowed values are ERROR and INFO.
	ErrCodeSubscriptionSeverityNotFoundFault = "SubscriptionSeverityNotFound"

	// ErrCodeTableLimitExceededFault for service response error code
	// "TableLimitExceeded".
	//
	// The number of tables in the cluster exceeds the limit for the requested new
	// cluster node type.
	ErrCodeTableLimitExceededFault = "TableLimitExceeded"

	// ErrCodeTableRestoreNotFoundFault for service response error code
	// "TableRestoreNotFoundFault".
	//
	// The specified TableRestoreRequestId value was not found.
	ErrCodeTableRestoreNotFoundFault = "TableRestoreNotFoundFault"

	// ErrCodeTagLimitExceededFault for service response error code
	// "TagLimitExceededFault".
	//
	// You have exceeded the number of tags allowed.
	ErrCodeTagLimitExceededFault = "TagLimitExceededFault"

	// ErrCodeUnauthorizedOperation for service response error code
	// "UnauthorizedOperation".
	//
	// Your account is not authorized to perform the requested operation.
	ErrCodeUnauthorizedOperation = "UnauthorizedOperation"

	// ErrCodeUnauthorizedPartnerIntegrationFault for service response error code
	// "UnauthorizedPartnerIntegration".
	//
	// The partner integration is not authorized.
	ErrCodeUnauthorizedPartnerIntegrationFault = "UnauthorizedPartnerIntegration"

	// ErrCodeUnknownSnapshotCopyRegionFault for service response error code
	// "UnknownSnapshotCopyRegionFault".
	//
	// The specified region is incorrect or does not exist.
	ErrCodeUnknownSnapshotCopyRegionFault = "UnknownSnapshotCopyRegionFault"

	// ErrCodeUnsupportedOperationFault for service response error code
	// "UnsupportedOperation".
	//
	// The requested operation isn't supported.
	ErrCodeUnsupportedOperationFault = "UnsupportedOperation"

	// ErrCodeUnsupportedOptionFault for service response error code
	// "UnsupportedOptionFault".
	//
	// A request option was specified that is not supported.
	ErrCodeUnsupportedOptionFault = "UnsupportedOptionFault"

	// ErrCodeUsageLimitAlreadyExistsFault for service response error code
	// "UsageLimitAlreadyExists".
	//
	// The usage limit already exists.
	ErrCodeUsageLimitAlreadyExistsFault = "UsageLimitAlreadyExists"

	// ErrCodeUsageLimitNotFoundFault for service response error code
	// "UsageLimitNotFound".
	//
	// The usage limit identifier can't be found.
	ErrCodeUsageLimitNotFoundFault = "UsageLimitNotFound"
)
