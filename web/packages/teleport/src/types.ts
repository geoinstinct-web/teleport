/*
Copyright 2020 Gravitational, Inc.

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

import React from 'react';

import {
  ManagementSection,
  NavigationCategory,
} from 'teleport/Navigation/categories';

export type NavGroup = 'team' | 'activity' | 'clusters' | 'accessrequests';

export interface Context {
  init(): Promise<void>;
  getFeatureFlags(): FeatureFlags;
}

export interface TeleportFeatureNavigationItem {
  title: NavTitles;
  icon: React.ReactNode;
  exact?: boolean;
  getLink?(clusterId: string): string;
  isExternalLink?: boolean;
}

export type NavTitle = `${NavTitles}`;

export enum NavTitles {
  // Resources
  Servers = 'Servers',
  Applications = 'Applications',
  Kubernetes = 'Kubernetes',
  Databases = 'Databases',
  Desktops = 'Desktops',
  AccessRequests = 'Access Requests',
  ActiveSessions = 'Active Sessions',

  // Management
  //  Access
  Users = 'Users',
  Roles = 'Roles',
  TrustedDevices = 'Trusted Devices',
  AuthConnectors = 'Auth Connectors',
  SessionAndIdentityLocks = 'Session & Identity Locks',
  Integrations = 'Integrations',
  EnrollNewResource = 'Enroll New Resource',
  EnrollNewIntegration = 'Enroll New Integration',
  NewRequest = 'New Request',
  ReviewRequests = 'Review Requests',

  // Activity
  SessionRecordings = 'Session Recordings',
  AuditLog = 'Audit Log',

  // Billing
  BillingSummary = 'Summary',
  PaymentsAndInvoices = 'Payments and Invoices',
  InvoiceSettings = 'Invoice Settings',

  // Clusters
  ManageClusters = 'Manage Clusters',
  TrustedClusters = 'Trusted Clusters',

  // Account
  AccountSettings = 'Account Settings',
  HelpAndSupport = 'Help & Support',

  Support = 'Support',
  Downloads = 'Downloads',
}

export interface TeleportFeatureRoute {
  title: string;
  path: string;
  exact?: boolean;
  component: React.FunctionComponent;
}

export interface TeleportFeature {
  parent?: new () => TeleportFeature | null;
  category?: NavigationCategory;
  section?: ManagementSection;
  hasAccess(flags: FeatureFlags): boolean;
  // route defines react router Route fields.
  // This field can be left undefined to indicate
  // this feature is a parent to children features
  // eg: FeatureAccessRequests is parent to sub features
  // FeatureNewAccessRequest and FeatureReviewAccessRequests.
  // These childrens will be responsible for routing.
  route?: TeleportFeatureRoute;
  navigationItem?: TeleportFeatureNavigationItem;
  topMenuItem?: TeleportFeatureNavigationItem;
  // alternative items to display when the user has permissions (RBAC)
  // but the cluster lacks the feature:
  isLocked?(lockedFeatures: LockedFeatures): boolean;
  lockedNavigationItem?: TeleportFeatureNavigationItem;
  lockedRoute?: TeleportFeatureRoute;
}

export type StickyCluster = {
  clusterId: string;
  hasClusterUrl: boolean;
  isLeafCluster: boolean;
};

export type Label = {
  name: string;
  value: string;
};

// TODO: create a better abscraction for a filter, right now it's just a label
export type Filter = {
  value: string;
  name: string;
  kind: 'label';
};

export interface FeatureFlags {
  audit: boolean;
  recordings: boolean;
  authConnector: boolean;
  roles: boolean;
  trustedClusters: boolean;
  users: boolean;
  applications: boolean;
  kubernetes: boolean;
  billing: boolean;
  databases: boolean;
  desktops: boolean;
  nodes: boolean;
  activeSessions: boolean;
  accessRequests: boolean;
  newAccessRequest: boolean;
  downloadCenter: boolean;
  discover: boolean;
  plugins: boolean;
  integrations: boolean;
  enrollIntegrationsOrPlugins: boolean;
  enrollIntegrations: boolean;
  deviceTrust: boolean;
  locks: boolean;
  newLocks: boolean;
  assist: boolean;
}

// LockedFeatures are used for determining which features are disabled in the user's cluster.
export type LockedFeatures = {
  authConnectors: boolean;
  activeSessions: boolean;
  accessRequests: boolean;
  premiumSupport: boolean;
  trustedDevices: boolean;
};

// RecommendFeature is used for recommending features if its usage status is zero.
export type RecommendFeature = {
  TrustedDevices: RecommendationStatus;
};

export type RecommendationStatus = 'NOTIFY' | 'DONE';
